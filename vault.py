#!/usr/bin/python3

import base64
import os
from os import path
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class Vault:

  def __init__(self):
    # self.url = ''
    # self.username = ''
    self.password = ''
    self.key = b'' # your key will be stored here while you are using the program
    self.itemData = {} # dictionary to hold item data
    self.itemName = {} # dictionary to hold items by key


  def keyGen(self):
    password_provided = "hacktheplanet" # This is the password as a type string
    password = password_provided.encode() # Convert to type bytes
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend())

    # this creates your encryption key
    self.key = base64.urlsafe_b64encode(kdf.derive(password)) 

    # The key generated can only be used once so we write it to a file
    file = open('key', 'wb')
    file.write(self.key)
    file.close()


  def readKey(self):
    file = open('key', 'rb')
    self.key = file.read()
    file.close()


  def addItem(self):
    '''takes user input and stores it in the dictionary itemData'''

    url = input('Enter URL Address: ')
    username = input('Enter username: ')
    self.password = input('Enter password: ')

    # adds item data to the dictionary
    self.itemData = {'URL': url, 'Username': username}


  def encryptData(self):
    '''encrypts the password field of the dictionary'''

    if path.exists('key'):
      self.readKey()
    else:
      self.keyGen()

# the encrypt function  needs bytes so we encode it
    userPwd = self.password.encode()

    # this encrypts the password
    f = Fernet(self.key)
    encryptedPwd = f.encrypt(userPwd)

    # json will not write bytes so we decode it to utf-8, then add it to the dictionary
    self.itemData['Password'] = encryptedPwd.decode('utf-8')


  def writeData(self):
    '''writes new entry to json file'''

# this is to store each entry with a specific label
    itemlabel = input("Enter the name of the new item: ")

    # if file does not exist we create it
    # if file does exist we read in the data, append new data, write back to file
    if path.exists("myVault.json"):
      print("Vault exists! ")
      fin = open('myVault.json', 'r')
      self.itemName = json.load(fin)
      fin.close()
      # we are appending new data here
      self.itemName[itemlabel] = self.itemData

      print("Updating vault... ")
      fout = open("myVault.json", 'w')
      json.dump(self.itemName, fout, sort_keys=True)
      fout.close()
      print('Vault updated!!')
    else:
      print('No vault found! \n Creating a new vault...')

      self.itemName[itemlabel] = self.itemData
      fout = open("myVault.json", 'w+')
      json.dump(self.itemName, fout)
      fout.close()
      print('Vault created! \n Data written!!')


  def updateData(self):
    print('Updating vault... ')
    fout = open("myVault.json", 'w')
    json.dump(self.itemName, fout, sort_keys=True)
    fout.close()
    print('Vault updated! ')


  def readData(self):
    print('Reading in data...')
    # load the dictionary
    fin = open('myVault.json', 'r')
    self.itemName = json.load(fin)
    fin.close()
    print('Data has been read into dictionary!')


  def decryptData(self):
    '''decrypts the data and displays it'''

    # read the key for use in decryption
    self.readKey()

    # this is the name for the stored item
    userQuery = input("Enter the name of the item to get: ")

    # calls readData method so the dictionary will contain data
    self.readData()

    # loads the query data into the itemData dictionary
    self.itemData = self.itemName.get(userQuery)

    # assigns each field of the data to a variable
    url = self.itemData.get('URL')
    uname = self.itemData.get('Username')
    pwd = self.itemData.get('Password').encode()

    f = Fernet(self.key)
    decryptedPassword = f.decrypt(pwd)

    # displays each field
    print('URL: ', url)
    print('Username: ', uname)
    print('Password: ', decryptedPassword)


  def displayItems(self):
    '''Displays all of the item names in the vault'''

    fin = open('myVault.json', 'r')
    self.itemName = json.load(fin)
    fin.close()
    
    print('The items you have stored are: ')
    for key in self.itemName:
      print(key)


  def removeItem(self):
    '''Removes an item from the vault'''

    itemToRemove = input("Enter the name of the item you want to remove: ")

    # Calls readData method so dictionarys contain data
    self.readData()

    # calls del method to remove item
    del self.itemName[itemToRemove]
    print(itemToRemove, 'has been removed from the vault!')

    # Calls updateData method to update data in vault
    self.updateData()


  def displayOptions(self):
    '''displays the options for user interaction'''
    print("Welcome to My Vault! \n My vault will store your private data and encrypt your passwords! \n Enter the number of the task you would like to perform")

    task = input("1. Add new item: \n 2. Retreav item data: \n 3. Display list of item names: \n 4. Remove item: \n 5. Will secure your data and exit!")

    return task


if __name__ == "__main__":
  v = Vault()
  flag = True
  while flag:
    userOption = v.displayOptions()
    if userOption == '1':
      v.addItem()
      print("Encrypting data...")
      v.encryptData()
      print("Data encrypted!")
      v.writeData()
    elif userOption == '2':
      print("Decrypting data...")
      v.decryptData()
      print('Data decrypted!')
    elif userOption == '3':
      v.displayItems()
    elif userOption == '4':
      v.removeItem()
    elif userOption == '5':
      print("Exiting My Vault! Securing your data")
      flag = False
    else:
      print("Please enter a valid number!")

