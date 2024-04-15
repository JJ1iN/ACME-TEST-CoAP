#
#	testNOD.py
#
#	(c) 2020 by Andreas Kraft
#	License: BSD 3-Clause License. See the LICENSE file for further details.
#
#	Unit tests for NOD functionality & notifications
#

import unittest, sys
import requests
if '..' not in sys.path:
	sys.path.append('..')
from typing import Tuple
from acme.etc.Types import ResourceTypes as T, ResponseStatusCode as RC
from init import *

nodeID  = 'urn:sn:1234'
nod2RN 	= 'test2NOD'
nod2URL = f'{cseURL}/{nod2RN}'


class TestNOD(unittest.TestCase):

	cse  		= None
	ae 			= None
	nodeRI 		= None
	aeRI 		= None
	originator	= None

	@classmethod
	@unittest.skipIf(noCSE, 'No CSEBase')
	def setUpClass(cls) -> None:
		testCaseStart('Setup TestNOD')
		cls.cse, rsc = RETRIEVE(cseURL, ORIGINATOR)
		assert rsc == RC.OK, f'Cannot retrieve CSEBase: {cseURL}'
		testCaseEnd('Setup TestNOD')
		

	@classmethod
	@unittest.skipIf(noCSE, 'No CSEBase')
	def tearDownClass(cls) -> None:
		if not isTearDownEnabled():
			return
		testCaseStart('TearDown TestNOD')
		DELETE(aeURL, ORIGINATOR)	# Just delete the AE and everything below it. Ignore whether it exists or not
		DELETE(nodURL, ORIGINATOR)	# Just delete the Node and everything below it. Ignore whether it exists or not
		DELETE(nod2URL, ORIGINATOR)	# Just delete the Node 2 and everything below it. Ignore whether it exists or not
		DELETE(f'{cseURL}/Ctest', ORIGINATOR)
		DELETE(f'{cseURL}/{nodRN}2', ORIGINATOR)

		testCaseEnd('TearDown TestNOD')


	def setUp(self) -> None:
		testCaseStart(self._testMethodName)
	

	def tearDown(self) -> None:
		testCaseEnd(self._testMethodName)


	#########################################################################


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_createNOD(self) -> None:
		""" Create <NOD> """
		self.assertIsNotNone(TestNOD.cse)
		dct = 	{ 'm2m:nod' : { 
					'rn' 	: nodRN,
					'ni'	: nodeID
				}}
		r, rsc = CREATE(cseURL, ORIGINATOR, T.NOD, dct)
		self.assertEqual(rsc, RC.CREATED)
		self.assertIsNotNone(findXPath(r, 'm2m:nod/ri'))
		TestNOD.nodeRI = findXPath(r, 'm2m:nod/ri')


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_retrieveNOD(self) -> None:
		""" Retrieve <NOD> """
		_, rsc = RETRIEVE(nodURL, ORIGINATOR)
		self.assertEqual(rsc, RC.OK)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_retrieveNODWithWrongOriginator(self) -> None:
		""" Retrieve <NOD> with wrong originator -> Fail """
		_, rsc = RETRIEVE(nodURL, 'Cwrong')
		self.assertEqual(rsc, RC.ORIGINATOR_HAS_NO_PRIVILEGE)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_attributesNOD(self) -> None:
		""" Retrieve <NOD> and test attributes """
		r, rsc = RETRIEVE(nodURL, ORIGINATOR)
		self.assertEqual(rsc, RC.OK)
		self.assertEqual(findXPath(r, 'm2m:nod/ty'), T.NOD)
		self.assertEqual(findXPath(r, 'm2m:nod/pi'), findXPath(TestNOD.cse,'m2m:cb/ri'))
		self.assertEqual(findXPath(r, 'm2m:nod/rn'), nodRN)
		self.assertIsNotNone(findXPath(r, 'm2m:nod/ct'))
		self.assertIsNotNone(findXPath(r, 'm2m:nod/lt'))
		self.assertIsNotNone(findXPath(r, 'm2m:nod/et'))
		self.assertIsNotNone(findXPath(r, 'm2m:nod/ni'))
		self.assertEqual(findXPath(r, 'm2m:nod/ni'), nodeID)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_updateNODLbl(self) -> None:
		""" Update <NOD> lbl """
		dct = 	{ 'm2m:nod' : {
					'lbl' : [ 'aTag' ]
				}}
		r, rsc = UPDATE(nodURL, ORIGINATOR, dct)
		self.assertEqual(rsc, RC.UPDATED)
		r, rsc = RETRIEVE(nodURL, ORIGINATOR)		# retrieve updated ae again
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(findXPath(r, 'm2m:nod/lbl'))
		self.assertIsInstance(findXPath(r, 'm2m:nod/lbl'), list)
		self.assertGreater(len(findXPath(r, 'm2m:nod/lbl')), 0)
		self.assertTrue('aTag' in findXPath(r, 'm2m:nod/lbl'))


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_updateNODUnknownAttribute(self) -> None:
		""" Update <NOD> with unknown attribute -> Fail """
		dct = 	{ 'm2m:nod' : {
					'unknown' : 'unknown'
				}}
		_, rsc = UPDATE(nodURL, ORIGINATOR, dct)
		self.assertEqual(rsc, RC.BAD_REQUEST)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_createAEForNOD(self) -> None:
		""" Create <AE> for <NOD> & test link """
		dct = 	{ 'm2m:ae' : {
			'rn'	: aeRN, 
			'api'	: APPID,
		 	'rr'	: False,
		 	'srv'	: [ RELEASEVERSION ],
		 	'nl' 	: TestNOD.nodeRI
		}}
		TestNOD.ae, rsc = CREATE(cseURL, 'C', T.AE, dct)
		self.assertEqual(rsc, RC.CREATED)
		self.assertIsNotNone(findXPath(TestNOD.ae, 'm2m:ae/nl'))
		self.assertEqual(findXPath(TestNOD.ae, 'm2m:ae/nl'), TestNOD.nodeRI)
		self.assertIsNotNone(findXPath(TestNOD.ae, 'm2m:ae/ri'))
		self.assertIsNotNone(findXPath(TestNOD.ae, 'm2m:ae/aei'))
		TestNOD.aeRI = findXPath(TestNOD.ae, 'm2m:ae/ri')
		TestNOD.originator = findXPath(TestNOD.ae, 'm2m:ae/aei')

		nod, rsc = RETRIEVE(nodURL, ORIGINATOR)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(findXPath(nod, 'm2m:nod/hael'), nod)
		self.assertIn(findXPath(TestNOD.ae, 'm2m:ae/ri'), findXPath(nod, 'm2m:nod/hael'))	# ae.ri in nod.hael?


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_deleteAEForNOD(self) -> None:
		""" Delete <AE> for <NOD> & test link """
		_, rsc = DELETE(aeURL, ORIGINATOR)
		self.assertEqual(rsc, RC.DELETED)

		nod, rsc = RETRIEVE(nodURL, ORIGINATOR)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNone(findXPath(nod, 'm2m:nod/hael'))	# should have been the only AE, so the attribute should now be removed


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_moveAEToNOD2(self) -> None:
		""" Create second <NOD> and move <AE> """
		# create AE again
		self.test_createAEForNOD()

		# create second node
		dct = 	{ 'm2m:nod' : { 
			'rn' 	: nod2RN,
			'ni'	: 'second'
		}}
		nod2, rsc = CREATE(cseURL, ORIGINATOR, T.NOD, dct)
		self.assertEqual(rsc, RC.CREATED)
		self.assertIsNotNone(findXPath(nod2, 'm2m:nod/ri'))
		self.assertEqual(findXPath(nod2, 'm2m:nod/rn'), nod2RN)
		node2RI = findXPath(nod2, 'm2m:nod/ri')

		# move AE to second NOD
		dct = 	{ 'm2m:ae' : { 
			'nl' : node2RI
		}}
		r, rsc = UPDATE(aeURL, TestNOD.originator, dct)
		self.assertEqual(rsc, RC.UPDATED)
		self.assertIsNotNone(findXPath(r, 'm2m:ae/nl'))
		self.assertEqual(findXPath(r, 'm2m:ae/nl'), node2RI)

		# Check first NOD
		nod, rsc = RETRIEVE(nodURL, ORIGINATOR)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNone(findXPath(nod, 'm2m:nod/hael'))	# should have been the only AE, so the attribute should now be removed

		# Check second NOD
		nod2, rsc = RETRIEVE(nod2URL, ORIGINATOR)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(findXPath(nod2, 'm2m:nod/hael')) 	
		self.assertEqual(len(findXPath(nod2, 'm2m:nod/hael')), 1)
		self.assertIn(TestNOD.aeRI, findXPath(nod2, 'm2m:nod/hael'))


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_deleteNOD2(self) -> None:
		""" Delete second <NOD> """
		_, rsc = DELETE(nod2URL, ORIGINATOR)
		self.assertEqual(rsc, RC.DELETED)

		# Check AE
		ae, rsc = RETRIEVE(aeURL, ORIGINATOR)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNone(findXPath(ae, 'm2m:ae/nl'))	# should have been the only AE, so the attribute should now be removed


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_deleteNOD(self) -> None:
		""" Delete <NOD> """
		_, rsc = DELETE(nodURL, ORIGINATOR)
		self.assertEqual(rsc, RC.DELETED)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_createNODEmptyHael(self) -> None:
		""" Create <NOD> with empty hael list -> Fail"""
		self.assertIsNotNone(TestNOD.cse)
		dct = 	{ 'm2m:nod' : { 
					'rn' 	: nodRN,
					'ni'	: nodeID,
					'hael'	: []
				}}
		r, rsc = CREATE(cseURL, ORIGINATOR, T.NOD, dct)
		self.assertEqual(rsc, RC.BAD_REQUEST, r)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_createNODDoubleHael(self) -> None:
		""" Create <NOD> with a pre-set hael list, add <AE> with nl attribute"""
		self.assertIsNotNone(TestNOD.cse)
		dct = 	{ 'm2m:nod' : { 
					'rn' 	: f'{nodRN}2',
					'ni'	: nodeID,
					'hael'	: [ 'Ctest']
				}}
		r, rsc = CREATE(cseURL, ORIGINATOR, T.NOD, dct)
		self.assertEqual(rsc, RC.CREATED, r)
		self.assertIsNotNone(findXPath(r, 'm2m:nod/hael'), r)
		self.assertEqual(len(findXPath(r, 'm2m:nod/hael')), 1, r)
		_nlri = findXPath(r, 'm2m:nod/ri')

		# Register AE
		dct2 = 	{ 'm2m:ae' : {
			'rn'	: 'Ctest', 
			'api'	: APPID,
		 	'rr'	: False,
		 	'srv'	: [ RELEASEVERSION ],
		 	'nl' 	: _nlri
		}}
		r2, rsc = CREATE(cseURL, 'Ctest', T.AE, dct2)
		self.assertEqual(rsc, RC.CREATED)
		_aeri = findXPath(r2, 'm2m:ae/ri')

		# Check NOD
		nod, rsc = RETRIEVE(f'{cseURL}/{nodRN}2', ORIGINATOR)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(findXPath(nod, 'm2m:nod/hael'))
		self.assertEqual(len(findXPath(nod, 'm2m:nod/hael')), 1)
		self.assertIn(_aeri, findXPath(nod, 'm2m:nod/hael'))

		# Delete AE and NOD
		_, rsc = DELETE(f'{cseURL}/Ctest', ORIGINATOR)
		self.assertEqual(rsc, RC.DELETED)
		_, rsc = DELETE(f'{cseURL}/{nodRN}2', ORIGINATOR)
		self.assertEqual(rsc, RC.DELETED)


def run(testFailFast:bool) -> Tuple[int, int, int, float]:
	suite = unittest.TestSuite()
			
	addTest(suite, TestNOD('test_createNOD'))
	addTest(suite, TestNOD('test_retrieveNOD'))
	addTest(suite, TestNOD('test_retrieveNODWithWrongOriginator'))
	addTest(suite, TestNOD('test_attributesNOD'))
	addTest(suite, TestNOD('test_updateNODLbl'))
	addTest(suite, TestNOD('test_updateNODUnknownAttribute'))
	addTest(suite, TestNOD('test_createAEForNOD'))
	addTest(suite, TestNOD('test_deleteAEForNOD'))
	addTest(suite, TestNOD('test_moveAEToNOD2'))
	addTest(suite, TestNOD('test_deleteNOD2'))
	addTest(suite, TestNOD('test_deleteNOD'))
	addTest(suite, TestNOD('test_createNODEmptyHael'))
	addTest(suite, TestNOD('test_createNODDoubleHael'))
	
	result = unittest.TextTestRunner(verbosity=testVerbosity, failfast=testFailFast).run(suite)
	printResult(result)
	return result.testsRun, len(result.errors + result.failures), len(result.skipped), getSleepTimeCount()


if __name__ == '__main__':
	r, errors, s, t = run(True)
	sys.exit(errors)
