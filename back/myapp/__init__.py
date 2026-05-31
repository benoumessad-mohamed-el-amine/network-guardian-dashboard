# Monkeypatch to support unpickling of older ColumnTransformer objects on newer scikit-learn versions
try:
    import sklearn.compose._column_transformer as ct
    if not hasattr(ct, '_RemainderColsList'):
        class DummyRemainderColsList(list):
            pass
        ct._RemainderColsList = DummyRemainderColsList
except ImportError:
    pass

# Suppress noisy warnings
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", category=ResourceWarning)
