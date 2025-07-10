# ruff: noqa: PGH003,ANN001,ANN002,ANN003,ANN201,ANN202,ANN204,D101
# type: ignore
"""Test the metaclass used to deprecated things.

https://stackoverflow.com/a/52087847 by
Kentzo https://stackoverflow.com/users/188530/kentzo
"""

from requests_oauth2client.deprecated import _DeprecatedClassMeta


class NewClass:
    foo = 1


class NewClassSubclass(NewClass):
    pass


class DeprecatedClass(metaclass=_DeprecatedClassMeta):
    _DeprecatedClassMeta__alias = NewClass


class DeprecatedClassSubclass(DeprecatedClass):
    foo = 2


class DeprecatedClassSubSubclass(DeprecatedClassSubclass):
    foo = 3


def test_deprecating_metaclass():
    assert issubclass(DeprecatedClass, DeprecatedClass)
    assert issubclass(DeprecatedClassSubclass, DeprecatedClass)
    assert issubclass(DeprecatedClassSubSubclass, DeprecatedClass)
    assert issubclass(NewClass, DeprecatedClass)
    assert issubclass(NewClassSubclass, DeprecatedClass)

    assert issubclass(DeprecatedClassSubclass, NewClass)
    assert issubclass(DeprecatedClassSubSubclass, NewClass)

    assert isinstance(DeprecatedClass(), DeprecatedClass)
    assert isinstance(DeprecatedClassSubclass(), DeprecatedClass)
    assert isinstance(DeprecatedClassSubSubclass(), DeprecatedClass)
    assert isinstance(NewClass(), DeprecatedClass)
    assert isinstance(NewClassSubclass(), DeprecatedClass)

    assert isinstance(DeprecatedClassSubclass(), NewClass)
    assert isinstance(DeprecatedClassSubSubclass(), NewClass)

    assert NewClass().foo == 1
    assert DeprecatedClass().foo == 1
    assert DeprecatedClassSubclass().foo == 2
    assert DeprecatedClassSubSubclass().foo == 3
