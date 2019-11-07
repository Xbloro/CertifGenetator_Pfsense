#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" create by Yug0h on 02/19
    This script allow u to creat cert on pfsense
    This is V2 in  OOP	
"""

###################################################### Import ##################################################################
import requests
import sys
import re 
import bs4
import urllib
from bs4 import BeautifulSoup
import getopt
#################################################################################################################################

######################################################  CLASS ###################################################################

class PfSenseCertificate(object):

	""" 
	Class PfSenseCertificate 
	- allow user to create certificate
	- allow user to get and download  a certificate
	"""

#""""""""""""""""""""""""""""""""""" Constructeur """"""""""""""""""""""""""""""""""""""""""
	
	def __init__(self, url, login, password): 
		"""
		Constructor of the class
		
		:param url : The base URl of the platform
		:type url : Type string
		:param login : The login id  of the platform
		:type login : Type string
		:param password : The password id  of the platform
		:type password : Type string
		
		"""
		
		self.m_url = url
		self.m_urlsite = url
		self.m_login = login
		self.m_pass = password
		
		
#"""""""""""""""""""""""""""""""""" END constructeur """"""""""""""""""""""""""""""""""""""""""

#""""""""""""""""""""""""""""""""""" Getter Setter """""""""""""""""""""""""""""""""""""""""""""

	#"""""" M_LOGIN """""""""""
	@property
	def m_login(self): #getter
		return self.__m_login
		
	@m_login.setter	#setter 
	def m_login(self,value):
		try :
			if isinstance(value, str) != True :		
				raise ValueError("error please provide a str input")
				
			self.__m_login = value
		except : 
			raise
	#""""" END M_LOGIN"""""""


	#"""""" M_PASS """""""""""
	@property
	def m_pass(self): #getter 
		return self.__m_pass
		
	@m_pass.setter	#setter 
	def m_pass(self,value):
		try :
			if isinstance(value, str) != True :		
				raise ValueError("error please  provide a str input")
			self.__m_pass = str(value)
		except : 
			raise
	#""""" END M_PASS"""""""
	
	
	#"""""" M_URL """""""""""
	@property
	def m_url(self): #getter de m_url
		return self.__m_url
		
	@m_url.setter	#setter de m_url
	def m_url(self,value):
		try :
			if isinstance(value, str) != True :		
				raise ValueError("error please  provide a str input")
			self.__m_url = str(value)
		except :
			raise	
	#""""" END M_URL"""""""
	
	#"""""" M_URLSite """""""""""
	@property
	def m_urlsite(self): #getter de m_url
		return self.__m_urlsite
		
	@m_urlsite.setter	#setter de m_url
	def m_urlsite(self,value):
		try :
			if isinstance(value, str) != True :		
				raise ValueError("error please  provide a str input")
			self.__m_urlsite = str(value)
		except : 
			raise
	#""""" END M_URLSite"""""""
	
	
#"""""""""""""""""""""""""""""""""""""""""""" END Getter Setter """""""""""""""""""""""""""""""""""""""	

#"""""""""""""""""""""""""""""""""""""""""" Fontions Membres """"""""""""""""""""""""""""""""""

	def __gen_payloadConnexion(self,csrf,login,passwd): #Define the connexion payload
		"""
		Generate the payload for the connexion Page
		
		:param csrf : csrf token from previous connection
		:type csrf : Type string
		:param login : The login id  of the platform
		:type login : Type string
		:param passwd : The password id  of the platform
		:type passwd : Type string
		"""
		m_payloadConnexion = {'__csrf_magic':csrf,'usernamefld':login, 'passwordfld':passwd, 'login':'Sign+In'}
		return m_payloadConnexion
	
	def __gen_payloadCertificat(self,csrf,name,n_days,key2) : #define the certif payload
	
		"""
		Generate the payload for the certificaye

		:param name : The name of the certificate
		:type name : Type string
		:param n_days : The number of days of validity of the certificate
		:type n_days : Type string
		"""
		m_payloadCertificat = {"__csrf_magic":csrf,"method":"internal","descr":name,"catosignwith":key2,"csrtosign":"new","csrpaste":"",
		"keypaste":"","csrsign_lifetime":"3650","csrsign_digest_alg":"sha256","cert":"","key":"","caref":key2,"keylen":"2048","digest_alg":"sha256",
		"lifetime":n_days,"dn_commonname":name,"dn_country":"","dn_state":"","dn_city":"","dn_organization":"","dn_organizationalunit":"","csr_keylen":"2048",
		"csr_digest_alg":"sha256","csr_dn_commonname":"","csr_dn_country":"","csr_dn_state":"","csr_dn_city":"","csr_dn_organization":"","csr_dn_organizationalunit":"",
		"certref":key2,"type":"user","altname_type0":"DNS","altname_value0":name,"save":"Save"}
		return m_payloadCertificat
	
	def __create_dic_from_lists(self,liste1,liste2): # return dic with list1 as key and liste2 as value -> dic{list1 : list2}
	
		"""
		Create a dictionnary with 2 lists, first list will be key and 2nd list arg
		
		:param liste1 :  list of keys
		:type liste1 : Type list
		:param liste2 :  list of value
		:type liste2 : Type list

		"""
		dic = {}
		for i in range(len(liste1)):
			dic[liste1[i]] = liste2[i]
		return dic
	

	def __get_key(self): #get the key of pfsense for the certificate
		"""
		get the key of pfsense for the certificate
		"""
		try:
			session1 = requests.session()
			page1 = self.__connect_site(session1,self.m_login,self.m_pass)
			page1 = self.__get_page(session1,self.m_urlsite + "system_certmanager.php?act=new")
			ret = re.search(r'id=\"caref\"\>\s*<option value=\"(.*)\"', page1.text).group(1)
			return ret  
		except :
			print("failled to get the key") 


	def __get_certif_names(self,text): #return a list containing all certif names
		"""
		Get a list of certificate name from a text
		
		:param text :  text to search for name
		:type text : Type string
		"""
		return re.findall(r'(?<=\s)(CN=.*?)(?=,?\s)', text)
		
	def __get_dl_links(self,text): #return a list containing all certif download links
		"""
		Get a list of all certificat's dowload link from a text
		
		:param text :  text to search for name
		:type text : Type string
		"""
		l = re.findall(r'system_certmanager.php\?act=exp&amp.id=\d', text)
		lout = []
		for i in l : 
			i = self.m_urlsite + i 
			i = i.replace(';','&')
			lout.append(i)
		return lout

	def __get_dl_links_keys(self,text): #return a list containing all certif keys download links
		"""
		Get a list of all certificat's  KEY dowload link from a text
		
		:param text :  text to search for name
		:type text : Type string
		"""
		l = re.findall(r'system_certmanager.php\?act=key&amp.id=\d', text)
		lout = []
		for i in l : 
			i = self.m_urlsite + i 
			i = i.replace(';','&')
			lout.append(i)
		return lout


	def __get_certif_dl_link_key(self,text,name): #return the download key links of the certificate
		"""
		Get the download key link of a certificate
		
		:param text :  text to search for name
		:type text : Type string
		:param name : the name of the certificate we are looking for
		:type name : str 
		"""
		dic = self.__create_dic_from_lists(self.__get_certif_names(text),self.__get_dl_links_keys(text))
		return dic[name]

	def __get_certif_dl_link(self,text,name): #return the download links of the certificate
		"""
		Get the download link of a certificate
		
		:param text :  text to search for name
		:type text : Type string
		:param name : the name of the certificate we are looking for
		:type name : str 
		"""
		dic = self.__create_dic_from_lists(self.__get_certif_names(text),self.__get_dl_links(text))
		return dic[name]
	
	def __get_csrf(self,text): #retrun csrf token in a page
		"""
		Get the download csrf token from a text
		
		:param text :  text to search for csrf 
		:type text : Type string
		"""
		ret = re.search(r'var csrfMagicToken = "(.+)"(;?)var', text).group(1) #Le csrf de connection 
		return ret
		
	def __get_cookies(self,session): #return session cookies
		"""
		Get the cookies from a session
		
		:param session :  session from requests 
		:type session : Type requests obj
		"""
		return session.cookies
		
	def __get_certif_bin(self,session,url,cookie): #return the download certificate as bytes
		"""
		Get the binary of file from download url

		:param session :  session from requests 
		:type session : Type requests obj
		:param url :  the download url of the file
		:type url : Type string
		:param cookie : cookies of the session
		:type cookie : Type requests.cookies
		"""
		return session.get(url, cookies=cookie, verify=False).content
		
	def __get_page(self,session,url): #http/s get on page, return result, no verification
		"""
		perform http/s get on a page and return resuslts

		:param session :  session from requests 
		:type session : Type requests obj
		:param url :  the url to get
		:type url : Type string
		"""
		try : 
			page = session.get(url, verify=False, timeout=10)

		except requests.exceptions.Timeout as e : 
			print("Connection timeout exiting")
			print(e)
			exit()
		except : 
			print("error getting on url  : "+ url)
			print(page.status_code, page.reason) #debug
		return page 
	
	def __post_page(self,session,url,cookie,payload): #http/s post on page, return result, no verification
		"""
		perform a post on a page

		:param session :  session from requests 
		:type session : Type requests obj
		:param url : the url to post
		:type url : Type string
		:param cookie : cookies of the session
		:type cookie : Type requests.cookies
		:param payload : arguments to be posted on the url
		:type payload : Type dic
		"""
		try : 
			page = session.post(url, data=payload, cookies=cookie, verify=False, timeout=10) 

		except requests.exceptions.Timeout as e : 
			print("Connection timeout exiting")
			print(e)
			exit()
		except : 
			print("error posting on url  : "+ url)
			print(page.status_code, page.reason) #debug
		return page	
	
	def __connect_site(self,sess,login,password): #connect to the site and return info of the session
		"""
		connect to a site 
		
		:param session :  session from requests 
		:type session : Type requests obj
		:param login : The login id  of the platform
		:type login : Type string
		:param passwd : The password id  of the platform
		:type passwd : Type string
		"""
		session = sess
		self.m_url = self.m_urlsite + "system_certmanager.php"
		print("connecting to url : " + self.m_url)
		page = self.__get_page(session, self.m_url)
		page = self.__post_page(session, self.m_url, self.__get_cookies(session),self.__gen_payloadConnexion(self.__get_csrf(page.text),login,password))
		return page
		
	def __check_cert_name(self,name): #check if a certif with a name given exist
		"""
		check if the name of a certificate already exist
	
		:param name : the name of the certificate we are looking for
		:type name : str 
		"""
		session1 = requests.session()
		page1 = self.__connect_site(session1,self.m_login,self.m_pass)
		page1 = self.__get_page(session1,self.m_urlsite + "system_certmanager.php")
		names = self.__get_certif_names(page1.text)
		if name in names :
			#print("certif exist")
			return True
		else : 
			#print("certif does not exist")
			return False
	
	def create_cert(self,name,days):	#create a certificate on the platform
		"""
		allow an user to create a certificate on the platform

		:param name : The name of the certificate
		:type name : Type string
		:param n_days : The number of days of validity of the certificate
		:type n_days : Type string
		"""
		try:
			if isinstance(name,str) != True : 
				raise ValueError("must provide a str")
		except : 
			raise
		try:
			if isinstance(days,str) != True : 
				raise ValueError("must provide a str")
		except : 
			raise
			
		isValide = self.__check_cert_name("CN="+name)
		try : 
			if isValide == False : 
				session = requests.session()
				page = self.__connect_site(session,self.m_login,self.m_pass) 
				self.m_url = self.m_urlsite + "system_certmanager.php"
				page = self.__get_page(session,self.m_url)
				key = self.__get_key()
				page = self.__post_page(session, self.m_url,self.__get_cookies(session),self.__gen_payloadCertificat(self.__get_csrf(page.text),name,days,key))
			else :
				raise ValueError('certificate already exist')
		except : 
			print("certif name : " + name + " already exist, it won't be created .")
			
	def dl_cert(self,name): #download a certificate

		"""
		allow an user to download a  certificate on the platform
		
		:param name : The name of the certificate
		:type name : Type string
		"""
		try:
			if isinstance(name,str) != True : 
				raise ValueError("must provide a str")
		except : 
			raise
		isValide = self.__check_cert_name("CN="+name)
		try : 
			if isValide == True : 
				session = requests.session()
				page = self.__connect_site(session,self.m_login,self.m_pass) 
				self.m_url = self.m_urlsite + "system_certmanager.php"
				page = self.__get_page(session,self.m_url) 
				certi = self.__get_certif_bin(session,self.__get_certif_dl_link(page.text,"CN="+name),self.__get_cookies(session))
				key = self.__get_certif_bin(session,self.__get_certif_dl_link_key(page.text,"CN="+name),self.__get_cookies(session))
				return certi, key 
			else :
				raise ValueError('certificate : ' + name + ' does not exist, passing trough ')
		except : 
			print('certificate : ' + name + ' does not exist, passing trough ')
		

		
	
#"""""""""""""""""""""""""""""""""""""""""" End Fontions Membres """"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
#################################################################################################################################

		
################################################## MAIN #########################################################################
def createCertif(url,login,passwd,name,dayz):
	test = PfSenseCertificate(url,login,passwd)
	test.create_cert(name,dayz)

def createCertifAll(url,login,passwd,name,dayz,nbcert):
	for i in range(0,int(nbcert)):
		nametp = name + str(i)
		print("creating certif : " + nametp)
		test = PfSenseCertificate(url,login,passwd)
		test.create_cert(nametp,dayz)

def dlCertif(url,login,passwd,name,path):
	namefile = name + ".crt"
	namekey = name + "Key" + ".crt"
	print("téléchargement du fichier : " + namefile)
	test = PfSenseCertificate(url,login,passwd)
	try : 
		cert, key = test.dl_cert(name)
	except : 
		print("err getting cert and key : " + name )
	try : 
		open(path + namefile, 'wb').write(cert)
		open(path + namekey, 'wb').write(key)
	except : 
		print("cert download error, passing")


def usage():
	print("")
	print("########################## HELP ##############################")
	print("")
	print("------- Auth section -------------")
	print(" usage : -l : --login= : login ID : type str : required = true")
	print(" usage : -p : --password= : password ID : type str : required = true")
	print(" usage : -u : --url= : url of the platform : type str : required = true")
	print("")

	print("------- Create section -------------")
	print(" usage : -C : --Create : Create a certificate : required = false")
	print(" usage : -c : --certNameCreate= : certif name : type str :required = true if -C")
	print(" usage : -t : --timerCert= : lifetime of the certif, in dayz : type Str : required : true if -C ")
	print(" usage : -n : --nbCertif= : number of certificate to create : type str : required = false")
	print(" if not on it will create only 1 certificate")
	print(" if On name of the certif will inc by 1 ex : name = G >> G1, G2..GN")
	print("")

	print("------- Download section -------------")
	print(" usage : -D : --Download : Download a certificate : required = false")
	print(" usage : -d : --dlCertName= : Dl certif name  : type str : required = if -D")
	print(" usage : -P : --Path= : Path to save files  : type str : required = if -D")
	print("")

	print(" usage : -h : --help= : show this help : required = false")
	print(" arg -C OR -D is required")


if __name__ == "__main__":

################################################################ GESTION DES ARGUMENTS ######################################################################################
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'l:p:u:Cc:n:t:Dd:P:h', ['login=', 'password=','url=','Create','certNameCreate=','nbCertif=','timeCert==','Download','dlCertName=','Path=', 'help'])
		found_l = False
		found_p = False
		found_u = False
		found_C = False
		found_c = False
		found_t = False
		found_n = False
		found_D = False
		found_d = False
		found_P = False
		
	except getopt.GetoptError:
		usage()
		sys.exit(2)
	for opt, arg in opts:
		if opt in ('-h', '--help'):
			usage()
			sys.exit(2)
		elif opt in ('-l', '--login'):
			e_login = arg
			found_l = True
		elif opt in ('-p', '--password'):
			e_password = arg
			found_p = True
		elif opt in ('-u', '--url'):
			e_url = arg
			found_u = True
		elif opt in ('-C', '--Create'):
			e_create = True
			found_C = True
		elif opt in ('-c', '--certNameCreate'):
			e_certNameCreate = arg
			found_c = True
		elif opt in ('-n', '--nbCertif'):
			e_nbCertif = arg
			found_n = True
		elif opt in ('-t', '--timeCert'):
			e_timeCert = arg
			found_t = True
		elif opt in ('-D', '--Download'):
			e_Download = True
			found_D = True
		elif opt in ('-d', '--dlCertName'):
			e_dlCertName = arg
			print(e_dlCertName)
			found_d = True
		elif opt in ('-P', '--Path'):
			e_Path = arg
			found_P = True
		else:
			usage()
			sys.exit(2)

	if found_C == False and found_D == False:
		print("   /!\ must provide something to do /!|")
		usage()
		sys.exit(2)

	if found_C == True: #si on créé
		if found_c == False or found_t == False : 
			print("   /!\ must provide a name AND date for the certificate /!| ")
			usage()
			sys.exit(2)

	if found_D == True : 
		if found_d == False or found_P == False : 
			print("please provide Name or path ")
			usage()
			sys.exit(2)
	
################################################ instruction ##################################################################################
	
	if found_C == True : #creation de certif
		if found_n == False : #création d'un seul certif 
			createCertif(e_url,e_login,e_password,e_certNameCreate,e_timeCert)
		else : # création de plusieur certif 
			createCertifAll(e_url,e_login,e_password,e_certNameCreate,e_timeCert,e_nbCertif)
	
	if found_D == True :
		dlCertif(e_url,e_login,e_password,e_dlCertName,e_Path)
