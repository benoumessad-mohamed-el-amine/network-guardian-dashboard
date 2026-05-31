# Monkeypatch to support unpickling of older ColumnTransformer objects on newer scikit-learn versions
try:
    import sklearn.compose._column_transformer as ct
    if not hasattr(ct, '_RemainderColsList'):
        class DummyRemainderColsList(list):
            pass
        ct._RemainderColsList = DummyRemainderColsList
except ImportError:
    pass
