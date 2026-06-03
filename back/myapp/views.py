from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from django.db import models
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from django.contrib.auth.models import User
from .models import TrafficLog, Alert, AccessLog
from .serializers import (
    TrafficLogSerializer,
    AlertSerializer,
    PacketInferenceSerializer,
    RegisterSerializer,
    LoginSerializer,
    UserSerializer,
    AccessLogSerializer,
)
from .processing.model_factory import create_model
from .processing.service import PacketAnalysisService
from .sniffer_manager import SnifferManager

sniffer_manager = SnifferManager()

# Original Views for Authentication
def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})

@login_required
def home(request):
    return render(request, 'home.html')


@api_view(['GET'])
@permission_classes([AllowAny])
def api_setup_status(request):
    return Response({'needs_setup': not User.objects.exists()})


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def api_register(request):
    if User.objects.exists() and not (request.user.is_authenticated and request.user.is_staff):
        return Response({'error': 'Only administrators can create new accounts.'}, status=status.HTTP_403_FORBIDDEN)
        
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )
        if user:
            login(request, user)
            ip = request.META.get('REMOTE_ADDR')
            AccessLog.objects.create(user=user, action='LOGIN', ip_address=ip)
            return Response({'message': 'Login successful'})
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def api_logout(request):
    if request.user.is_authenticated:
        ip = request.META.get('REMOTE_ADDR')
        AccessLog.objects.create(user=request.user, action='LOGOUT', ip_address=ip)
    logout(request)
    return Response({'message': 'Logout successful'})


import random
import time
from django.core.mail import send_mail

# In-memory OTP storage for password resets: { username: { "otp": "123456", "expires_at": float, "user_id": int } }
otp_store = {}

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def api_user(request):
    if not request.user.is_authenticated:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if request.method == 'POST':
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        request.user.email = email
        request.user.save()
        return Response(UserSerializer(request.user).data)
        
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([AllowAny])
def api_forgot_password(request):
    identity = request.data.get('identity')  # username or email
    if not identity:
        return Response({'error': 'Username or Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Lookup user by username or email
    user = User.objects.filter(username=identity).first() or User.objects.filter(email=identity).first()
    if not user:
        return Response({'error': 'No user found with the provided username or email'}, status=status.HTTP_404_NOT_FOUND)
        
    if not user.email:
        return Response({'error': 'This user account has no associated email address. Please contact an administrator.'}, status=status.HTTP_400_BAD_REQUEST)
        
    # Generate a random 6-digit OTP code
    otp = str(random.randint(100000, 999999))
    
    # Store OTP in-memory with a 10-minute expiry
    otp_store[user.username] = {
        'otp': otp,
        'expires_at': time.time() + 600,
        'user_id': user.id
    }
    
    # Formulate email message
    subject = "Password Reset OTP - Sentinel Flow"
    message = f"""Hello {user.username},

You requested a password reset for your Soficlef Sentinel Flow IDS account.

Your One-Time Password (OTP) code is: {otp}

This OTP is valid for 10 minutes. If you did not request this reset, please ignore this email.

Best regards,
Soficlef Sentinel Security Systems Team
"""
    try:
        send_mail(
            subject,
            message,
            "security@soficlef.local",
            [user.email],
            fail_silently=False
        )
    except Exception as e:
        return Response({'error': f'Failed to send email: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    return Response({'message': 'OTP sent successfully to your registered email address.'})


@api_view(['POST'])
@permission_classes([AllowAny])
def api_reset_password(request):
    identity = request.data.get('identity')
    otp_code = request.data.get('otp')
    new_password = request.data.get('new_password')
    
    if not identity or not otp_code or not new_password:
        return Response({'error': 'Identity, OTP, and new password are required'}, status=status.HTTP_400_BAD_REQUEST)
        
    user = User.objects.filter(username=identity).first() or User.objects.filter(email=identity).first()
    if not user:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
    otp_record = otp_store.get(user.username)
    if not otp_record:
        return Response({'error': 'No active OTP request found for this account'}, status=status.HTTP_400_BAD_REQUEST)
        
    if time.time() > otp_record['expires_at']:
        del otp_store[user.username]
        return Response({'error': 'The OTP code has expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)
        
    if otp_record['otp'] != str(otp_code).strip():
        return Response({'error': 'Invalid OTP code. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)
        
    # Reset password
    user.set_password(new_password)
    user.save()
    
    # Log the password change event
    AccessLog.objects.create(user=user, action='LOGIN', ip_address=request.META.get('REMOTE_ADDR'))
    
    # Clear the OTP
    del otp_store[user.username]
    
    return Response({'message': 'Password has been reset successfully. You can now log in.'})


@api_view(['GET'])
@ensure_csrf_cookie
@permission_classes([AllowAny])
def get_csrf_token(request):
    return Response({'csrfToken': get_token(request)})


# API ViewSets
class TrafficLogViewSet(viewsets.ModelViewSet):
    queryset = TrafficLog.objects.all()
    serializer_class = TrafficLogSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['src_ip', 'dst_ip', 'protocol']
    ordering_fields = ['timestamp', 'byte_count', 'packet_count']
    ordering = ['-timestamp']
    permission_classes = [AllowAny]

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get traffic statistics"""
        total = TrafficLog.objects.count()
        protocols = TrafficLog.objects.values_list('protocol', flat=True).distinct().count()
        total_bytes = TrafficLog.objects.aggregate(total=models.Sum('byte_count'))['total'] or 0
        
        return Response({
            'total_logs': total,
            'unique_protocols': protocols,
            'total_bytes': total_bytes,
        })


# Load the hierarchical composite classifier if the pickle files exist,
# otherwise fallback to the mock model for development.
import os
import logging
logger = logging.getLogger(__name__)

models_dir = os.path.join(os.path.dirname(__file__), 'processing', 'models')
scaler_file = os.path.join(models_dir, 'network_scaler.pkl')

if os.path.exists(scaler_file):
    try:
        ml_model = create_model('hierarchical')
        ml_model.load(models_dir)
        logger.info("Successfully loaded Hierarchical IDS Models from processing/models/")
    except Exception as e:
        logger.error(f"Error loading Hierarchical IDS Models: {e}. Falling back to mock model.")
        ml_model = create_model('mock')
        ml_model.load('development')
else:
    logger.warning("No ML model folder/scaler found at processing/models/network_scaler.pkl. Falling back to mock model.")
    ml_model = create_model('mock')
    ml_model.load('development')

packet_analysis_service = PacketAnalysisService(ml_model)


@api_view(['POST'])
@permission_classes([AllowAny])
def api_packet_ingest(request):
    serializer = PacketInferenceSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    packet_payload = serializer.validated_data
    if packet_payload.get('packet_size', 0) == 0 and packet_payload.get('length'):
        packet_payload['packet_size'] = packet_payload['length']

    result, traffic_log, alert = packet_analysis_service.analyze_and_store(packet_payload)

    response_data = {
        'prediction': {
            'label': result.label,
            'score': result.score,
            'features': result.features,
        },
        'traffic_log_id': traffic_log.id,
        'alert_id': alert.id if alert else None,
    }
    return Response(response_data, status=status.HTTP_201_CREATED)


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'severity', 'source_ip']
    ordering_fields = ['timestamp', 'severity']
    ordering = ['-timestamp']
    permission_classes = [AllowAny]

    @action(detail=False, methods=['get'])
    def unresolved(self, request):
        """Get unresolved alerts"""
        unresolved_alerts = Alert.objects.filter(is_resolved=False).order_by('-timestamp')[:100]
        serializer = self.get_serializer(unresolved_alerts, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def by_severity(self, request):
        """Get alerts grouped by severity"""
        critical = Alert.objects.filter(severity='CRITICAL').count()
        high = Alert.objects.filter(severity='HIGH').count()
        medium = Alert.objects.filter(severity='MEDIUM').count()
        low = Alert.objects.filter(severity='LOW').count()
        
        return Response({
            'CRITICAL': critical,
            'HIGH': high,
            'MEDIUM': medium,
            'LOW': low,
        })

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve an alert"""
        alert = self.get_object()
        alert.is_resolved = True
        alert.save()
        return Response({'status': 'Alert resolved'})


class AccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AccessLog.objects.all()
    serializer_class = AccessLogSerializer
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']
    permission_classes = [IsAdminUser]


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAdminUser])
def api_sniffer_start(request):
    interface = request.data.get('interface')
    success, message = sniffer_manager.start(interface=interface)
    if success:
        return Response({'message': message})
    return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAdminUser])
def api_sniffer_stop(request):
    success, message = sniffer_manager.stop()
    if success:
        return Response({'message': message})
    return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def api_sniffer_status(request):
    return Response(sniffer_manager.status())


@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_sniffer_interfaces(request):
    return Response(sniffer_manager.interfaces())


from .processing import model_wrappers

@csrf_exempt
@api_view(['GET', 'POST'])
@permission_classes([IsAdminUser])
def api_sniffer_threshold(request):
    if request.method == 'POST':
        try:
            val = float(request.data.get('threshold'))
            if 0.0 <= val <= 1.0:
                model_wrappers.set_anomaly_threshold(val)
                response = Response({'threshold': model_wrappers.get_anomaly_threshold()})
                response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
                return response
            return Response({'error': 'Threshold must be between 0.0 and 1.0'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    else:
        response = Response({'threshold': model_wrappers.get_anomaly_threshold()})
        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response


import json
from django.http import StreamingHttpResponse

@api_view(['GET'])
@permission_classes([AllowAny])
def api_dashboard_stream(request):
    """
    Server-Sent Events (SSE) endpoint to stream real-time logs, unresolved alerts,
    statistics, and sniffer status to the frontend.
    """
    def event_stream():
        # Keep track of last sent IDs to send only deltas
        last_log_id = TrafficLog.objects.aggregate(max_id=models.Max('id'))['max_id'] or 0
        last_alert_id = Alert.objects.aggregate(max_id=models.Max('id'))['max_id'] or 0
        
        # Initial snapshot data
        initial_logs = TrafficLog.objects.all().order_by('-timestamp')[:50]
        unresolved_alerts = Alert.objects.filter(is_resolved=False).order_by('-timestamp')[:100]
        total = TrafficLog.objects.count()
        protocols = TrafficLog.objects.values_list('protocol', flat=True).distinct().count()
        total_bytes = TrafficLog.objects.aggregate(total=models.Sum('byte_count'))['total'] or 0
        sniffer_status = sniffer_manager.status()
        
        # Serialize initial data
        from .serializers import TrafficLogSerializer, AlertSerializer
        logs_serializer = TrafficLogSerializer(initial_logs, many=True)
        alerts_serializer = AlertSerializer(unresolved_alerts, many=True)
        
        init_data = {
            'type': 'init',
            'logs': logs_serializer.data,
            'alerts': alerts_serializer.data,
            'stats': {
                'total_logs': total,
                'unique_protocols': protocols,
                'total_bytes': total_bytes,
            },
            'sniffer': sniffer_status
        }
        
        yield f"data: {json.dumps(init_data)}\n\n"
        
        last_stats_hash = (total, protocols, total_bytes)
        last_sniffer_hash = (sniffer_status.get('is_running'), sniffer_status.get('interface'))
        
        # Keep connection alive and send deltas
        while True:
            time.sleep(1)
            
            # Check for new logs
            new_logs = TrafficLog.objects.filter(id__gt=last_log_id).order_by('id')
            new_alerts = Alert.objects.filter(id__gt=last_alert_id).order_by('id')
            
            log_list = []
            if new_logs.exists():
                last_log_id = new_logs.last().id
                log_list = TrafficLogSerializer(new_logs, many=True).data
                
            alert_list = []
            if new_alerts.exists():
                last_alert_id = new_alerts.last().id
                alert_list = AlertSerializer(new_alerts, many=True).data
                
            # Check stats
            total = TrafficLog.objects.count()
            protocols = TrafficLog.objects.values_list('protocol', flat=True).distinct().count()
            total_bytes = TrafficLog.objects.aggregate(total=models.Sum('byte_count'))['total'] or 0
            current_stats_hash = (total, protocols, total_bytes)
            
            # Check sniffer
            current_sniffer = sniffer_manager.status()
            current_sniffer_hash = (current_sniffer.get('is_running'), current_sniffer.get('interface'))
            
            if log_list or alert_list or current_stats_hash != last_stats_hash or current_sniffer_hash != last_sniffer_hash:
                update_data = {
                    'type': 'update',
                    'new_logs': log_list,
                    'new_alerts': alert_list,
                    'stats': {
                        'total_logs': total,
                        'unique_protocols': protocols,
                        'total_bytes': total_bytes,
                    },
                    'sniffer': current_sniffer
                }
                yield f"data: {json.dumps(update_data)}\n\n"
                
                last_stats_hash = current_stats_hash
                last_sniffer_hash = current_sniffer_hash

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response