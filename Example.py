#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import Pfsense as auto



def createCertifAll(name,dayz,path):
	namefile=name+".crt"
	test = auto.PfSenseCertificate("https://192.168.1.1/","admin","pfsense")
	test.create_cert(name,dayz)
	open(path + namefile, 'wb').write(test.dl_cert(name))

	


################################################## MAIN #########################################################################

if __name__ == "__main__":
	
	nom = "G"
	for i in range(1,5): # creating 5 certif named G1, G2 ...
		print("création du certificat : " +str(i))
		nomcap = nom+str(i)
		createCertifAll(nomcap,"50","/home/darkvador/Téléchargements/")
		

