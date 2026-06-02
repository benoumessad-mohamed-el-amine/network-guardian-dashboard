import { createFileRoute } from "@tanstack/react-router";
import { useAuth, api } from "@/context/auth-context";
import { User, Shield, Gauge } from "lucide-react";
import { useState, useEffect } from "react";
import { Slider } from "@/components/ui/slider";
import { toast } from "sonner";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
});

function SettingsPage() {
  const { user, checkUser } = useAuth();
  const [threshold, setThreshold] = useState<number>(0.85);
  const [isSaving, setIsSaving] = useState(false);
  const [email, setEmail] = useState(user?.email || "");
  const [isUpdatingEmail, setIsUpdatingEmail] = useState(false);

  useEffect(() => {
    if (user?.email) {
      setEmail(user.email);
    }
  }, [user]);

  useEffect(() => {
    if (user?.is_staff) {
      api.get(`/sniffer/threshold/?_t=${Date.now()}`)
        .then((res) => {
          setThreshold(res.data.threshold);
        })
        .catch((err) => console.error("Failed to fetch detection threshold", err));
    }
  }, [user]);

  const handleUpdateEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsUpdatingEmail(true);
    try {
      await api.post("/auth/user/", { email });
      await checkUser();
      toast.success("Email address updated successfully!");
    } catch (err: any) {
      console.error("Failed to update email", err);
      toast.error(err.response?.data?.error || "Failed to update email address");
    } finally {
      setIsUpdatingEmail(false);
    }
  };

  const handleThresholdChange = (val: number[]) => {
    setThreshold(val[0]);
  };

  const saveThreshold = () => {
    setIsSaving(true);
    api.post("/sniffer/threshold/", { threshold })
      .then((res) => {
        setThreshold(res.data.threshold);
        toast.success("Anomaly detection sensitivity updated successfully!");
      })
      .catch((err) => {
        console.error("Failed to update threshold", err);
        toast.error("Failed to update detection sensitivity");
      })
      .finally(() => setIsSaving(false));
  };
  
  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight">Account Settings</h1>
        <p className="text-sm text-muted-foreground">
          View your profile details and configure engine sensitivity parameters.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-6 h-fit">
          <div className="flex items-center gap-4 border-b border-border pb-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <User className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">{user?.username}</h2>
              <p className="text-xs text-muted-foreground">
                {user?.is_staff ? "System Administrator" : "Security Analyst"}
              </p>
            </div>
          </div>
          <form onSubmit={handleUpdateEmail} className="space-y-4 pt-4 border-b border-border pb-4">
            <div className="space-y-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Email Address
              </label>
              <div className="flex gap-2">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="e.g. admin@soficlef.local"
                  className="flex-1 rounded-md border border-border bg-muted/20 px-3 py-1.5 text-xs text-foreground placeholder-muted-foreground/60 transition-all focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
                />
                <button
                  type="submit"
                  disabled={isUpdatingEmail || email === user?.email}
                  className="inline-flex h-8 items-center justify-center rounded-md bg-primary px-3 text-xs font-semibold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-40"
                >
                  {isUpdatingEmail ? "Saving..." : "Update"}
                </button>
              </div>
              <p className="text-[10px] text-muted-foreground leading-normal">
                Associating an email enables password reset authentication via One-Time Verification codes (OTP).
              </p>
            </div>
          </form>
          <div className="pt-4">
            <div className="flex items-center gap-2 text-sm">
              <Shield className="h-4 w-4 text-muted-foreground" />
              <span className="font-medium">Role:</span>
              <span className="rounded-md bg-muted px-2 py-0.5 text-xs font-semibold uppercase">
                {user?.is_staff ? "Administrator" : "Analyst"}
              </span>
            </div>
            <p className="mt-2 text-xs text-muted-foreground leading-normal">
              Your role defines what actions you can take within the IDS dashboard. Administrators have full system access.
            </p>
          </div>
        </div>

        {user?.is_staff && (
          <div className="rounded-lg border border-border bg-card p-6">
            <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <Gauge className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-base font-semibold">IDS Detection Sensitivity</h2>
                <p className="text-xs text-muted-foreground">Controls unknown anomaly sensitivity. Attack-specific detectors (portscan, DDoS, etc.) are unaffected.</p>
              </div>
            </div>

            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-sm font-medium">Unknown Anomaly Threshold</span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Higher values reduce false "Unknown Anomaly" alerts. Attack-type detections are always active.
                  </p>
                </div>
                <span className="text-lg font-bold text-primary font-mono">
                  {Math.round(threshold * 100)}%
                </span>
              </div>

              <div className="py-2">
                <Slider
                  value={[threshold]}
                  onValueChange={handleThresholdChange}
                  min={0.10}
                  max={0.99}
                  step={0.01}
                />
                <div className="flex justify-between text-[10px] text-muted-foreground mt-2 font-mono">
                  <span>10% (High Noise)</span>
                  <span>50% (Default)</span>
                  <span>85% (Recommended)</span>
                  <span>99% (Strict Anomaly)</span>
                </div>
              </div>

              <button
                onClick={saveThreshold}
                disabled={isSaving}
                className="inline-flex h-9 items-center justify-center rounded-md bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-50"
              >
                {isSaving ? "Saving Settings..." : "Save Anomaly Settings"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
