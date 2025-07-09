"""Mark a class as deprecated.

https://stackoverflow.com/a/52087847
"""
from warnings import warn


class DeprecatedClassMeta(type):
    def __new__(cls, name, bases, classdict, *args, **kwargs):
        alias = classdict.get("_DeprecatedClassMeta__alias")

        if alias is not None:
            def new(cls, *args, **kwargs):
                alias = cls._DeprecatedClassMeta__alias

                if alias is not None:
                    warn(f"{cls.__name__} has been renamed to {alias.__name__}, the alias will be "
                         "removed in the future", DeprecationWarning, stacklevel=2)

                return alias(*args, **kwargs)

            classdict["__new__"] = new
            classdict["__doc__"] = f"(Use {alias.__name__} instead of this class)"
            classdict["_DeprecatedClassMeta__alias"] = alias

        fixed_bases = []

        for b in bases:
            alias = getattr(b, "_DeprecatedClassMeta__alias", None)

            if alias is not None:
                warn(f"{b.__name__} has been renamed to {alias.__name__}, the alias will be "
                     "removed in the future", DeprecationWarning, stacklevel=2)

            # Avoid duplicate base classes.
            b = alias or b
            if b not in fixed_bases:
                fixed_bases.append(b)

        fixed_bases = tuple(fixed_bases)

        return super().__new__(cls, name, fixed_bases, classdict,
                               *args, **kwargs)

    def __instancecheck__(cls, instance):
        return any(cls.__subclasscheck__(c)
            for c in {type(instance), instance.__class__})

    def __subclasscheck__(cls, subclass):
        if subclass is cls:
            return True
        return issubclass(subclass, cls._DeprecatedClassMeta__alias)
