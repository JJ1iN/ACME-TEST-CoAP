#
#	testFCNT.py
#
#	(c) 2020 by Andreas Kraft
#	License: BSD 3-Clause License. See the LICENSE file for further details.
#
#	Unit tests for FCNT functionality & notifications
#

import unittest, sys
import requests
if '..' not in sys.path:
	sys.path.append('..')
from typing import Tuple
from acme.etc.Types import ResourceTypes as T, ResponseStatusCode as RC
from init import *


CND = 'org.onem2m.common.moduleclass.temperature'

class TestFCNT_FCI(unittest.TestCase):

	ae 			= None 
	originator 	= None

	@classmethod
	@unittest.skipIf(noCSE, 'No CSEBase')
	def setUpClass(cls) -> None:
		testCaseStart('Setup TestFCNT_FCI')
		dct = 	{ 'm2m:ae' : {
					'rn': aeRN, 
					'api': APPID,
					'rr': False,
					'srv': [ RELEASEVERSION ]
				}}
		cls.ae, rsc = CREATE(cseURL, 'C', T.AE, dct)	# AE to work under
		assert rsc == RC.CREATED, 'cannot create parent AE'
		cls.originator = findXPath(cls.ae, 'm2m:ae/aei')
		testCaseEnd('Setup TestFCNT_FCI')


	@classmethod
	@unittest.skipIf(noCSE, 'No CSEBase')
	def tearDownClass(cls) -> None:
		if not isTearDownEnabled():
			return
		testCaseStart('TearDown TestFCNT_FCI')
		DELETE(aeURL, ORIGINATOR)	# Just delete the AE and everything below it. Ignore whether it exists or not
		testCaseEnd('TearDown TestFCNT_FCI')


	def setUp(self) -> None:
		testCaseStart(self._testMethodName)
	

	def tearDown(self) -> None:
		testCaseEnd(self._testMethodName)


	#########################################################################


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_createFCNT(self) -> None:
		"""	Create a <FCNT> """
		self.assertIsNotNone(TestFCNT_FCI.ae)
		dct = 	{ 'cod:tempe' : { 
					'rn'	: fcntRN,
					'cnd' 	: CND, 
					'curT0'	: 23.0,
					'unit'	: 1,
					'minVe'	: -100.0,
					'maxVe' : 100.0,
					'steVe'	: 0.5,
					'mni'	: 10
				}}
		r, rsc = CREATE(aeURL, TestFCNT_FCI.originator, T.FCNT, dct)
		self.assertEqual(rsc, RC.CREATED)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_attributesFCNT(self) -> None:
		"""	Validate <FCNT> attributes """
		r, rsc = RETRIEVE(fcntURL, TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.OK, r)
		self.assertEqual(findXPath(r, 'cod:tempe/ty'), T.FCNT, r)
		self.assertEqual(findXPath(r, 'cod:tempe/pi'), findXPath(TestFCNT_FCI.ae,'m2m:ae/ri'), r)
		self.assertEqual(findXPath(r, 'cod:tempe/rn'), fcntRN, r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/ct'), r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/lt'), r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/et'), r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/st'), r)
		self.assertIsNone(findXPath(r, 'cod:tempe/cr'), r)
		self.assertEqual(findXPath(r, 'cod:tempe/cnd'), CND, r)
		self.assertEqual(findXPath(r, 'cod:tempe/curT0'), 23.0, r)
		self.assertIsNone(findXPath(r, 'cod:tempe/tarTe'), r)
		self.assertEqual(findXPath(r, 'cod:tempe/unit'), 1, r)
		self.assertEqual(findXPath(r, 'cod:tempe/minVe'), -100.0, r)
		self.assertEqual(findXPath(r, 'cod:tempe/maxVe'), 100.0, r)
		self.assertEqual(findXPath(r, 'cod:tempe/steVe'), 0.5, r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/st'), r)
		self.assertEqual(findXPath(r, 'cod:tempe/st'), 0, r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/mni'), r)
		self.assertEqual(findXPath(r, 'cod:tempe/mni'), 10, r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/cni'), r)
		self.assertEqual(findXPath(r, 'cod:tempe/cni'), 1, r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/cbs'), r)
		self.assertGreater(findXPath(r, 'cod:tempe/cbs'), 0, r)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_updateFCNT(self) -> None:
		"""	Update <FCNT> """
		dct = 	{ 'cod:tempe' : {
					'tarTe':   5.0,
					'curT0'	: 17.0,
				}}
		r, rsc = UPDATE(fcntURL, TestFCNT_FCI.originator, dct)
		self.assertEqual(rsc, RC.UPDATED)
		r, rsc = RETRIEVE(fcntURL, TestFCNT_FCI.originator)		# retrieve fcnt again
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(findXPath(r, 'cod:tempe/tarTe'))
		self.assertIsInstance(findXPath(r, 'cod:tempe/tarTe'), float)
		self.assertEqual(findXPath(r, 'cod:tempe/tarTe'), 5.0)
		self.assertEqual(findXPath(r, 'cod:tempe/curT0'), 17.0)
		self.assertEqual(findXPath(r, 'cod:tempe/st'), 1, r)
		self.assertEqual(findXPath(r, 'cod:tempe/cni'), 2)
		self.assertGreater(findXPath(r, 'cod:tempe/cbs'), 0)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_retrieveFCNTLaOl(self) -> None:
		"""	Retrieve <FCI> via <FCNT>/la and <FCNT>/ol """
		r, rsc = RETRIEVE(f'{fcntURL}/la', TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe'))
		self.assertIsNotNone(findXPath(r, 'cod:tempe/curT0'))
		self.assertEqual(findXPath(r, 'cod:tempe/curT0'), 17.0, r)

		r, rsc = RETRIEVE(f'{fcntURL}/ol', TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(r)
		self.assertIsNotNone(findXPath(r, 'cod:tempe'))
		self.assertIsNotNone(findXPath(r, 'cod:tempe/curT0'))
		self.assertEqual(findXPath(r, 'cod:tempe/curT0'), 23.0, r)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_updateFCNTMni(self) -> None:
		""" Update <FCNT> MNI """
		dct = 	{ 'cod:tempe' : {
					'mni':   1,
				}}
		r, rsc = UPDATE(fcntURL, TestFCNT_FCI.originator, dct)
		self.assertEqual(rsc, RC.UPDATED)
		r, rsc = RETRIEVE(fcntURL, TestFCNT_FCI.originator)		# retrieve fcnt again
		self.assertEqual(rsc, RC.OK)
		self.assertEqual(findXPath(r, 'cod:tempe/mni'), 1)
		self.assertEqual(findXPath(r, 'cod:tempe/cni'), 1)
		self.assertEqual(findXPath(r, 'cod:tempe/st'), 2)

		rla, rsc = RETRIEVE(f'{fcntURL}/la', TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(rla)

		rol, rsc = RETRIEVE(f'{fcntURL}/ol', TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(rol)

		# al == ol ?
		self.assertEqual(findXPath(rla, 'cod:tempe/ri'), findXPath(rol, 'cod:tempe/ri'))


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_updateLBL(self) -> None:
		""" Update <FCNT> LBL """
		dct = 	{ 'cod:tempe' : {
					'lbl':	[ 'aLabel' ],
				}}
		r, rsc = UPDATE(fcntURL, TestFCNT_FCI.originator, dct)
		self.assertEqual(rsc, RC.UPDATED)
		self.assertIn('aLabel', findXPath(r, 'cod:tempe/lbl'))

		rla, rsc = RETRIEVE(f'{fcntURL}/la', TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(rla)
		self.assertIsNotNone(findXPath(rla, 'cod:tempe/lbl'))
		self.assertIn('aLabel', findXPath(rla, 'cod:tempe/lbl'))



	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_updateMNInoFCICreated(self) -> None:
		""" Update MNI, no <FCI> shall be created """
		r, rsc = RETRIEVE(fcntURL, TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.OK)
		cni = findXPath(r, 'cod:tempe/cni')

		dct = 	{ 'cod:tempe' : {
					'mni':	10,				# Increase mni again
				}}
		r, rsc = UPDATE(fcntURL, TestFCNT_FCI.originator, dct)
		self.assertEqual(rsc, RC.UPDATED)
		self.assertIn('aLabel', findXPath(r, 'cod:tempe/lbl'))
		self.assertEqual(cni, findXPath(r, 'cod:tempe/cni'))


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_createFCIFail(self) -> None:
		"""	Create a <FCI> -> Fail """
		self.assertIsNotNone(TestFCNT_FCI.ae)
		dct = 	{ 'cod:tempe' : { 
					'curT0'	: 23.0,
				}}
		r, rsc = CREATE(fcntURL, TestFCNT_FCI.originator, T.FCI, dct)
		self.assertEqual(rsc, RC.OPERATION_NOT_ALLOWED, r)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_updateFCIFail(self) -> None:
		"""	Update a <FCI> -> Fail """
		self.assertIsNotNone(TestFCNT_FCI.ae)
		# Retrieve the latest FCI
		rla, rsc = RETRIEVE(f'{fcntURL}/la', TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.OK)
		self.assertIsNotNone(rla)
		self.assertIsNotNone(findXPath(rla, 'cod:tempe'))
		# Update the latest
		dct = 	{ 'cod:tempe' : { 
					'curT0'	: 5.0,
				}}
		r, rsc = UPDATE(f'{fcntURL}/{findXPath(rla, "cod:tempe/rn")}', TestFCNT_FCI.originator, dct)
		self.assertEqual(rsc, RC.OPERATION_NOT_ALLOWED)
	

	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_updateFCNTMniNull(self) -> None:
		""" Update <FCNT> : set MNI to null"""
		dct = 	{ 'cod:tempe' : {
					'mni':   None,
				}}
		r, rsc = UPDATE(fcntURL, TestFCNT_FCI.originator, dct)
		self.assertEqual(rsc, RC.UPDATED)
		r, rsc = RETRIEVE(fcntURL, TestFCNT_FCI.originator)		# retrieve fcnt again
		self.assertEqual(rsc, RC.OK)
		self.assertIsNone(findXPath(r, 'cod:tempe/mni'))
		self.assertIsNone(findXPath(r, 'cod:tempe/cni'))

		rla, rsc = RETRIEVE(f'{fcntURL}/la', TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.NOT_FOUND)

		rol, rsc = RETRIEVE(f'{fcntURL}/ol', TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.NOT_FOUND)


	@unittest.skipIf(noCSE, 'No CSEBase')
	def test_deleteFCNT(self) -> None:
		""" Delete <FCNT> """
		_, rsc = DELETE(fcntURL, TestFCNT_FCI.originator)
		self.assertEqual(rsc, RC.DELETED)


# TODO other FCNT controlling attributes
# TODO Add similar tests from testCNT_CIN for mni, etc

def run(testFailFast:bool) -> Tuple[int, int, int, float]:
	suite = unittest.TestSuite()
			
	addTest(suite, TestFCNT_FCI('test_createFCNT'))
	addTest(suite, TestFCNT_FCI('test_attributesFCNT'))
	addTest(suite, TestFCNT_FCI('test_updateFCNT'))
	addTest(suite, TestFCNT_FCI('test_retrieveFCNTLaOl'))
	addTest(suite, TestFCNT_FCI('test_updateFCNTMni'))
	addTest(suite, TestFCNT_FCI('test_updateLBL'))
	addTest(suite, TestFCNT_FCI('test_updateMNInoFCICreated'))
	addTest(suite, TestFCNT_FCI('test_createFCIFail'))
	addTest(suite, TestFCNT_FCI('test_updateFCIFail'))
	addTest(suite, TestFCNT_FCI('test_updateFCNTMniNull'))
	addTest(suite, TestFCNT_FCI('test_deleteFCNT'))
	
	result = unittest.TextTestRunner(verbosity=testVerbosity, failfast=testFailFast).run(suite)
	printResult(result)
	return result.testsRun, len(result.errors + result.failures), len(result.skipped), getSleepTimeCount()


if __name__ == '__main__':
	r, errors, s, t = run(True)
	sys.exit(errors)

