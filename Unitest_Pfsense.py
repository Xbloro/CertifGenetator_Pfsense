#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import Pfsense 
import requests

################################################## TEST Unitaires de la fonction PFsense #######################################
class TestPfsense(unittest.TestCase):

	def test_constructeur(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		self.assertEqual(test.m_url,"https://192.168.1.1/")
		self.assertEqual(test.m_login,"admin")
		self.assertEqual(test.m_pass,"pfsense")
		
	def test_payload_co(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		payload = test._PfSenseCertificate__gen_payloadConnexion("csrf","admin","pfsense")
		self.assertEqual(payload['__csrf_magic'],"csrf")
		self.assertEqual(payload['usernamefld'],"admin")
		self.assertEqual(payload['passwordfld'],"pfsense")
	
	def test_payload_cert(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		payload = test._PfSenseCertificate__gen_payloadCertificat("csrf","hugo","10")
		self.assertEqual(payload['__csrf_magic'],"csrf")
		self.assertEqual(payload['descr'],"hugo")
		self.assertEqual(payload['dn_commonname'],"hugo")
		self.assertEqual(payload['altname_value0'],"hugo")
		self.assertEqual(payload['lifetime'],"10")
		
	def test_create_dic_from_lists(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		l1 = ['pomme','fraise','bannane']
		l2 = ['rouge','rose','jaune']
		dic = test._PfSenseCertificate__create_dic_from_lists(l1,l2)
		self.assertEqual(dic['pomme'],"rouge")
		self.assertEqual(dic['fraise'],"rose")
		self.assertEqual(dic['bannane'],"jaune")

	def test_get_certif_name(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		name = test._PfSenseCertificate__get_certif_names("1234 4zlekfjzoeifjzeif zoeifuzoif zefzio CN=HUGO osijdozi CN=test zqdq dz")
		self.assertEqual(name[0], 'CN=HUGO')
		self.assertEqual(name[1], "CN=test")

	def test_get_dl_link(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		liste = test._PfSenseCertificate__get_dl_links("1234 4zlekfjzoeifjzei system_certmanager.php?act=exp&amp;id=0 f zoeifuzoif zefzio CN=HUGO osijdozi CN=test zqdq d system_certmanager.php?act=exp&amp;id=1 z")
		self.assertEqual(liste[0], "https://192.168.1.1/system_certmanager.php?act=exp&amp&id=0")
		self.assertEqual(liste[1], "https://192.168.1.1/system_certmanager.php?act=exp&amp&id=1")

	def test_get_certif_dl_link(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		dic = test._PfSenseCertificate__get_certif_dl_link("1234 4zlekfjzoeifjzei system_certmanager.php?act=exp&amp;id=0 f zoeifuzoif zefzio CN=HUGO osijdozi CN=test zqdq d system_certmanager.php?act=exp&amp;id=1 z","CN=HUGO")
		self.assertEqual(dic,"https://192.168.1.1/system_certmanager.php?act=exp&amp&id=0")

	def test_get_csrf(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		csrf = test._PfSenseCertificate__get_csrf('zekfljezlfkzehjf ùpzefzef zefpioj var csrfMagicToken = "sid:70aceff886f2b618da337d717d256ad0e2dab0eb,1551175658";var csrfMagicName = "__csrf_magic"  scvoisdjfiozefsvnjisvn sdofijvsdiofjv ')
		self.assertEqual(csrf ,'sid:70aceff886f2b618da337d717d256ad0e2dab0eb,1551175658')

	def test_get_cookies(self):
		test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
		session = requests.session()
		get = session.get('https://192.168.1.1/', verify=False)
		cookies = test._PfSenseCertificate__get_cookies(get)
		self.assertEqual(cookies, get.cookies)

	#def test_get_certif_bin(self):
	#	test = Pfsense.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
	#	session = requests.session()
	#	cert = session.get('http://ipv4.download.thinkbroadband.com/5MB.zip',verify=False).content
	#	cert2 = test._PfSenseCertificate__get_certif_bin(session, 'http://ipv4.download.thinkbroadband.com/5MB.zip', session.cookies)
	#	self.assertEqual(cert,cert2)

################################################## MAIN #########################################################################

if __name__ == "__main__":
	
	unittest.main()

