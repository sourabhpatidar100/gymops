class SingletonMeta(type):
    """
    A metaclass for creating singleton classes.
    Ensures only one instance of the class exists.
    """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonMeta, cls).__call__(*args, **kwargs)
        return cls._instances[cls]