# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import binascii
import testtools

from kmip.core import enums
from kmip.pie.objects import ManagedObject, OpaqueObject
from kmip.pie import sqltypes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


class TestOpaqueObject(testtools.TestCase):
    """
    Test suite for OpaqueObject.
    """
    def setUp(self):
        super(TestOpaqueObject, self).setUp()

        # Encoding taken from Sections 3.1.5 of the KMIP 1.1 testing
        # documentation.
        self.bytes_a = (
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64')
        self.bytes_b = (
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x65')
        self.engine = create_engine('sqlite:///:memory:', echo=True)
        sqltypes.Base.metadata.create_all(self.engine)

    def tearDown(self):
        super(TestOpaqueObject, self).tearDown()

    def test_init(self):
        """
        Test that a OpaqueObject object can be instantiated.
        """
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE)

        self.assertEqual(obj.value, self.bytes_a)
        self.assertEqual(obj.opaque_type, enums.OpaqueDataType.NONE)
        self.assertEqual(obj.names, ['Opaque Object'])

    def test_init_with_args(self):
        """
        Test that a OpaqueObject object can be instantiated with all arguments.
        """
        obj = OpaqueObject(
            self.bytes_a,
            enums.OpaqueDataType.NONE,
            name='Test Opaque Object')

        self.assertEqual(obj.value, self.bytes_a)
        self.assertEqual(obj.opaque_type, enums.OpaqueDataType.NONE)
        self.assertEqual(obj.names, ['Test Opaque Object'])

    def test_get_object_type(self):
        """
        Test that the object type can be retrieved from the OpaqueObject.
        """
        expected = enums.ObjectType.OPAQUE_DATA
        obj = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        observed = obj.object_type
        self.assertEqual(expected, observed)

    def test_validate_on_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        construct a OpaqueObject.
        """
        args = (0, enums.OpaqueDataType.NONE)
        self.assertRaises(TypeError, OpaqueObject, *args)

    def test_validate_on_invalid_data_type(self):
        """
        Test that a TypeError is raised when an invalid data type is used to
        construct a OpaqueObject.
        """
        args = (self.bytes_a, 'invalid')
        self.assertRaises(TypeError, OpaqueObject, *args)

    def test_validate_on_invalid_name(self):
        """
        Test that a TypeError is raised when an invalid name value is used to
        construct a OpaqueObject.
        """
        args = (self.bytes_a, enums.OpaqueDataType.NONE)
        kwargs = {'name': 0}
        self.assertRaises(TypeError, OpaqueObject, *args, **kwargs)

    def test_repr(self):
        """
        Test that repr can be applied to a OpaqueObject.
        """
        obj = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        args = "value={0}, opaque_type={1}".format(
            binascii.hexlify(self.bytes_a), enums.OpaqueDataType.NONE)
        expected = "OpaqueObject({0})".format(args)
        observed = repr(obj)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a OpaqueObject.
        """
        obj = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        expected = str(binascii.hexlify(self.bytes_a))
        observed = str(obj)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        OpaqueObject objects with the same data.
        """
        a = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns False when comparing two
        OpaqueObject objects with different data.
        """
        a = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = OpaqueObject(self.bytes_b, enums.OpaqueDataType.NONE)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data_type(self):
        """
        Test that the equality operator returns False when comparing two
        OpaqueObject objects with different data.
        """
        a = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b.opaque_type = "invalid"
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        OpaqueObject object to a non-OpaqueObject object.
        """
        a = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = "invalid"
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two OpaqueObject objects with the same internal data.
        """
        a = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns True when comparing two
        OpaqueObject objects with different data.
        """
        a = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = OpaqueObject(self.bytes_b, enums.OpaqueDataType.NONE)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data_type(self):
        """
        Test that the equality operator returns True when comparing two
        OpaqueObject objects with different data.
        """
        a = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b.opaque_type = "invalid"
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        OpaqueObject object to a non-OpaqueObject object.
        """
        a = OpaqueObject(self.bytes_a, enums.OpaqueDataType.NONE)
        b = "invalid"
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_save(self):
        """
        Test that the object can be saved using SQLAlchemy. This will add it to
        the database, verify that no exceptions are thrown, and check that its
        unique identifier was set.
        """
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE)
        Session = sessionmaker(bind=self.engine)
        session = Session()
        session.add(obj)
        session.commit()

    def test_get(self):
        """
        Test that the object can be saved and then retrieved using SQLAlchemy.
        This adds is to the database and then retrieves it by ID and verifies
        some of the attributes.
        """
        test_name = 'bowser'
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE, name=test_name)
        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(obj)
        session.commit()

        session = Session()
        get_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(1, len(get_obj.names))
        self.assertEqual([test_name], get_obj.names)
        self.assertEqual(self.bytes_a, get_obj.value)
        self.assertEqual(enums.ObjectType.OPAQUE_DATA, get_obj.object_type)
        self.assertEqual(enums.OpaqueDataType.NONE, get_obj.opaque_type)

    def test_add_multiple_names(self):
        """
        Test that multiple names can be added to a managed object. This
        verifies a few properties. First this verifies that names can be added
        using simple strings. It also verifies that the index for each
        subsequent string is set accordingly. Finally this tests that the names
        can be saved and retrieved from the database.
        """
        expected_names = ['bowser', 'frumpy', 'big fat cat']
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE, name=expected_names[0])
        obj.names.append(expected_names[1])
        obj.names.append(expected_names[2])
        self.assertEqual(3, obj.name_index)
        expected_mo_names = list()
        for i, name in enumerate(expected_names):
            expected_mo_names.append(sqltypes.ManagedObjectName(name, i))
        self.assertEqual(expected_mo_names, obj._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(obj)
        session.commit()

        session = Session()
        get_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_remove_name(self):
        """
        Tests that a name can be removed from the list of names. This will
        verify that the list of names is correct. It will verify that updating
        this object removes the name from the database.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        remove_index = 1
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE, name=names[0])
        obj.names.append(names[1])
        obj.names.append(names[2])
        obj.names.pop(remove_index)
        self.assertEqual(3, obj.name_index)

        expected_names = list()
        expected_mo_names = list()
        for i, name in enumerate(names):
            if i != remove_index:
                expected_names.append(name)
                expected_mo_names.append(sqltypes.ManagedObjectName(name, i))
        self.assertEqual(expected_names, obj.names)
        self.assertEqual(expected_mo_names, obj._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(obj)
        session.commit()

        session = Session()
        get_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_remove_and_add_name(self):
        """
        Tests that names can be removed from the list of names and more added.
        This will verify that the list of names is correct. It will verify that
        updating this object removes the name from the database. It will verify
        that the indices for the removed names are not reused.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE, name=names[0])
        obj.names.append(names[1])
        obj.names.append(names[2])
        obj.names.pop()
        obj.names.pop()
        obj.names.append('dog')
        self.assertEqual(4, obj.name_index)

        expected_names = ['bowser', 'dog']
        expected_mo_names = list()
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[0],
                                                            0))
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[1],
                                                            3))
        self.assertEqual(expected_names, obj.names)
        self.assertEqual(expected_mo_names, obj._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(obj)
        session.commit()

        session = Session()
        get_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_add_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will add a
        name to it in one session, and then retrieve it in another session to
        verify that it has all of the correct names.

        This test and the subsequent test_udpate_* methods are different than
        the name tests above because these are updating objects already stored
        in the database. This tests will simulate what happens when the KMIP
        client calls an add attribute method.
        """
        first_name = 'bowser'
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE, name=first_name)
        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(obj)
        session.commit()

        added_name = 'frumpy'
        expected_names = [first_name, added_name]
        expected_mo_names = list()
        for i, name in enumerate(expected_names):
            expected_mo_names.append(sqltypes.ManagedObjectName(name, i))

        session = Session()
        update_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        update_obj.names.append(added_name)
        session.commit()

        session = Session()
        get_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_remove_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will
        remove a name from it in one session, and then retrieve it in another
        session to verify that it has all of the correct names.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        remove_index = 1
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE, name=names[0])
        obj.names.append(names[1])
        obj.names.append(names[2])

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(obj)
        session.commit()

        expected_names = list()
        expected_mo_names = list()
        for i, name in enumerate(names):
            if i != remove_index:
                expected_names.append(name)
                expected_mo_names.append(sqltypes.ManagedObjectName(name, i))

        session = Session()
        update_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        update_obj.names.pop(remove_index)
        session.commit()

        session = Session()
        get_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_remove_and_add_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will
        remove a name and add another one to it in one session, and then
        retrieve it in another session to verify that it has all of the correct
        names. This simulates multiple operation being sent for the same
        object.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        obj = OpaqueObject(
            self.bytes_a, enums.OpaqueDataType.NONE, name=names[0])
        obj.names.append(names[1])
        obj.names.append(names[2])

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(obj)
        session.commit()

        session = Session()
        update_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        update_obj.names.pop()
        update_obj.names.pop()
        update_obj.names.append('dog')
        session.commit()

        expected_names = ['bowser', 'dog']
        expected_mo_names = list()
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[0],
                                                            0))
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[1],
                                                            3))

        session = Session()
        get_obj = session.query(OpaqueObject).filter(
            ManagedObject.unique_identifier == obj.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)
