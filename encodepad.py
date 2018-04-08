#!/usr/bin/python
#coding=utf-8

import sys
import string
import wx
import wx.adv
import urllib
import hashlib
import base64
import binascii
from Crypto.Hash import SHA,SHA256
from Crypto.Cipher import AES,DES,DES3,ARC4
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5


'''
Python encode tool pad in WxPython
Including all algorithm of encryption,as Base64,CRC32,Md5,RSA,AES,DES and so on
'''  

#gbk
def gbk( text ):
	return text.decode('gb2312')
	
#解析k-v
def urlcode( query ): 
	cstr = ''
	
	#mode
	tp = 1
	if query.find('%') <> -1:
		tp  = 2
		
	a = query.split('&')
	
	#split key value 
	if len(a) == 1:
		if tp == 1:
			cstr = urllib.quote( query )
		else:
			cstr = urllib.unquote( query )
		return cstr
	
	for s in a:
		if s.find('=') <> -1:
				if tp == 1:
					k,v = map(urllib.quote,s.split('='))	   #map将后面参数输入给func,reduce	 
				else:
					k,v = map(urllib.unquote,s.split('='))
				cstr += k +'=' + v + '&'
				
	return cstr[0:-1]
	
#base64
def bs64( tp,src ):
	if tp == 1:
		return base64.b64encode(src)
	else:
		try:
			return base64.b64decode(src)
		except TypeError:
			return 'Error'
	
#md5
def md5( src ):
	m2 = hashlib.md5()   
	m2.update(src)   
	return m2.hexdigest()
	
#crc32
def crc32( src ):
	return '0x%x' %(binascii.crc32(src) & 0xFFFFFFFF )
   

#DES
def des( tp,key,md,iv,src ):
	obj = DES.new(key,md, iv) 
	oUtil = DESPadder( obj,PAD_NORMAL )
	if tp == 1:
		return oUtil.encrypt(src)
	else:
		return oUtil.decrypt(src)

#DES3
def des3( tp,key,md,iv,src ):
	obj = DES3.new(key,md,iv)
	oUtil = DESPadder( obj,PAD_NORMAL )
	if tp == 1:
		return oUtil.encrypt(src)
	else:
		return oUtil.decrypt(src)
	
#AES 高级加密标准，下一代加密算法标准
def aes( tp,key,md,iv,src ):
	obj = AES.new(key,md, iv) 
	oUtil = DESPadder( obj,PAD_NORMAL,AES_TYPE )
	if tp == 1:
		return oUtil.encrypt(src)
	else:
		return oUtil.decrypt(src)


#sha
def sha( src ):
	hash = SHA256.new()
	hash.update(src)
	return hash.hexdigest()


random_generator = Random.new().read
#rsa算法生成实例
rsa = RSA.generate(1024, random_generator)


#rsa
def createRsaKey():
	private_pem = rsa.exportKey()

	with open('./private.pem', 'w') as f:
		f.write(private_pem)

	public_pem = rsa.publickey().exportKey()
	with open('./public.pem', 'w') as f:
		f.write(public_pem)
	
def rsaEncode( message ):
	with open('./public.pem') as f:
		 key = f.read()
		 rsakey = RSA.importKey(key)
		 cipher = Cipher_pkcs1_v1_5.new(rsakey)
		 cipher_text = base64.b64encode(cipher.encrypt(message))
		 return cipher_text

	return 'Rsa encode error'

def rsaDecode( message ):
	with open('./private.pem') as f:
		key = f.read()
		rsakey = RSA.importKey(key)
		cipher = Cipher_pkcs1_v1_5.new(rsakey)
		text = cipher.decrypt(base64.b64decode(message), random_generator)
		return text

	return 'Rsa decode error'
	

#补白方式   
PAD_NORMAL = 1
PAD_PKCS5 = 2
DES_TYPE = 8
AES_TYPE = 16


#填充
def PAD(x,tp=DES_TYPE):
	len_x = len(x)
	if len_x > 0 and len_x%tp == 0:
		return x
	
	filling = tp - len_x % tp
	return ( x + '\0' * filling )		  #强大的padding方式
  

#DES加解密
class DESPadder(object):
	def __init__(self, cipher, padmode,tp=DES_TYPE):
		self.cipher = cipher
		self.padmode = padmode
		self.tp = tp;
		
	#填充
	def _pad(self, x):
		len_x = len(x)
		filling = self.tp - len_x%self.tp
		if self.padmode == PAD_PKCS5:
			fill_char = chr(filling)
		else:
			fill_char = "\0"
		return ( x + fill_char * filling )		  #强大的padding方式
	
	#去补白
	def _unpad(self, x):
		if self.padmode == PAD_PKCS5:
			return x[0:-ord(x[-1])]
		return x.rstrip("\0")						   

	#加密
	def encrypt(self, x):
		return self.cipher.encrypt(self._pad(x))			#加密时补足key

	def decrypt(self, x):
		return self._unpad(self.cipher.decrypt(x))	  #解密后去除padding

'''
文本框输入较验证器
'''
class MyValidator(wx.PyValidator):
	def __init__(self,count=8):
		wx.PyValidator.__init__(self)
		self.count = count
		self.Bind(wx.EVT_CHAR, self.OnChar)

	def Clone(self):
		return MyValidator(self.count)
	
	#需要在OnChar主动调用Validate
	def Validate(self, win):
		tc = self.GetWindow()
		val = tc.GetValue()
		
		#限制长度
		if len(val) >= self.count:
			return False
		return True

	#输入屏蔽
	def OnChar(self, event):
		key = event.GetKeyCode()
		
		if key < wx.WXK_SPACE or key == wx.WXK_DELETE or key > 255:
			event.Skip()
			return
		
		if not wx.Validator_IsSilent():
			wx.Bell()
		
		#放过合适该数据
		if self.Validate(self.GetWindow() ):
			event.Skip()


#panel
class Toolpad(wx.Frame):
	#init
	def __init__(self,parent,title):
		wx.Frame.__init__(self,parent,-1,title,pos=(220,60),size=(800,700))
		panel = wx.Panel(self)
		
		self.InitComp(panel)
		self.setupMenuBar()
		ico = wx.Icon('images/app.ico',wx.BITMAP_TYPE_ICO)
		self.SetIcon( ico )
		
	def OnUrlcode(self,e):
		text = self.ulEdit.GetValue()
		cs = self.codeEdit.GetValue()
		if text == '':
			return
		
		text = text.encode(cs)
		dest = urlcode(text)
		try:
		  dest = dest.decode( cs )
		except UnicodeDecodeError:
		  dest = 'Unicode decode error'

		self.output.Clear()
		self.output.WriteText( dest )
	 
	def OnBase64encode(self,e):
		text = self.bsEdit.GetValue()
		if text == '':
			return
		
		dest = bs64(1,text)
		self.output.Clear()
		self.output.WriteText( dest )
	
	def OnBase64decode(self,e):
		text = self.bsEdit.GetValue()
		if text == '':
			return
		
		dest = bs64(2,text)
		self.output.Clear()
		self.output.WriteText( dest )
	 
	def OnMd5(self,e):
		text = self.md5Edit.GetValue()
		if text == '':
			return
		
		key = self.keyEdit.GetValue()
		text += key			 #拼接key
		dest = md5(text)
		self.output.Clear()
		self.output.WriteText( dest )
	
	#python未提供switch,基于dict实现，更简单
	modes = {'ECB':DES.MODE_ECB,
					'CBC':DES.MODE_CBC,
					'CFB':DES.MODE_CFB,
					'OFB':DES.MODE_OFB }
	
	def DESMode(self):
		md = self.dsAgEdit.GetValue()
		return self.modes.get(md)
	 
	def OnHex(self,e):
		text = self.hexEdit.GetValue()
		if text == '':
			return
		
		try:
			dest =  binascii.a2b_hex(text)
		except TypeError:
			dest = 'Error'

		self.output.Clear()
		self.output.WriteText( dest )
		   
	def OnCRC32(self,e):
		text = self.crEdit.GetValue()
		if text == '':
			return
		
		dest =  crc32(text)
		self.output.Clear()
		self.output.WriteText( dest )
	
	#RC4
	def OnRC4encode(self, e):
		text = self.rcEdit.GetValue()
		key = self.rcKeyEdit.GetValue()
		if text == '':
			return
		
		text = text.encode('gb2312')
		nonce = Random.new().read(16)	#unused
		tmpkey = SHA.new(key).digest()
		
		cipher = ARC4.new(tmpkey)
		dest = cipher.encrypt(text)
		self.output.Clear()
		self.output.WriteText( binascii.b2a_hex(dest) )
	
	def OnRC4decode(self, e):
		text = self.rcEdit.GetValue()
		key = self.rcKeyEdit.GetValue()
		if text == '':
			return
	
		try:
			text = text.decode('hex')
		except TypeError:
				return
			
		tmpkey = SHA.new(key).digest()
		cipher = ARC4.new(tmpkey)
		dest = cipher.decrypt(text)
		
		self.output.Clear()
		self.output.WriteText( gbk(dest) )
	
	#DES
	def OnDesencode(self,e):
		text = self.dsEdit.GetValue()
		if text == '':
			return
		
		#中文支持
		text = text.encode('gb2312')
		
		#长度必须为8
		key = PAD( self.dsKeyEdit.GetValue() )
		iv = PAD( self.dsivEdit.GetValue() )
		md = self.DESMode()
		dest =  des(1,key,md,iv,text)
		self.output.Clear()
		self.output.WriteText( binascii.b2a_hex(dest) )
		  
	def OnDesdecode(self,e):
		text = self.dsEdit.GetValue()
		if text == '':
			return
	
		try:
			text = text.decode('hex')
		except TypeError:
				return
			
		key = PAD( self.dsKeyEdit.GetValue() )
		iv = PAD( self.dsivEdit.GetValue() )
		md = self.DESMode()
		dest =  des(2,key,md,iv,text)
		
		self.output.Clear()
		self.output.WriteText( gbk(dest) )
	
	def OnDes3encode(self,e):
		text = self.d3Edit.GetValue()
		if text == '':
			return
		
		#中文支持
		text = text.encode('gb2312')
		
		key = PAD( self.d3KeyEdit.GetValue(),AES_TYPE )
		iv = PAD( self.d3ivEdit.GetValue() )
		md = self.DESMode()
		dest =  des3(1,key,md,iv,text)
		
		self.output.Clear()
		self.output.WriteText( binascii.b2a_hex(dest) )
		 
	def OnDes3decode(self,e):
		text = self.d3Edit.GetValue()
		if text == '':
			return
		
		#转化为16进制
		try:
			text = text.decode('hex')
		except TypeError:
				return
			
		key = PAD( self.d3KeyEdit.GetValue(),AES_TYPE )
		iv = PAD( self.d3ivEdit.GetValue() )
		md = self.DESMode()
		dest =  des3(2,key,md,iv,text)
		
		self.output.Clear()
		self.output.WriteText( gbk(dest) )
		   
	def OnAesencode(self,e):
		text = self.asEdit.GetValue()
		if text == '':
			return
		
		#中文支持
		text = text.encode('gb2312')
		
		#长度必须为16
		key = PAD( self.asKeyEdit.GetValue(),AES_TYPE )
		iv = PAD( self.asivEdit.GetValue(),AES_TYPE )
		md = self.DESMode()
		dest =  aes(1,key,md,iv,text)
		self.output.Clear()
		self.output.WriteText( binascii.b2a_hex(dest) )
		  
	def OnAesdecode(self,e):
		text = self.asEdit.GetValue()
		if text == '':
			return
		
		#hex
		try:
			text = text.decode('hex')
		except TypeError:
				return
			
		key = PAD( self.asKeyEdit.GetValue(),AES_TYPE )
		iv = PAD( self.asivEdit.GetValue(),AES_TYPE )
		md = self.DESMode()
		dest =  aes(2,key,md,iv,text)
		
		self.output.Clear()
		self.output.WriteText( gbk(dest) )
	
	def OnSha(self,e):
		text = self.shEdit.GetValue()
		if text == '':
			return
		
		dest = sha(text)
		self.output.Clear()
		self.output.WriteText( dest )
	
	#rsa
	def OnNewKey(self,e):
		createRsaKey()
		
	def OnRsaEncode(self,e):
		text = self.rsaEdit.GetValue()
		if text == '':
			return
		
		text = text.encode( 'gb2312' )
		dest = rsaEncode( text )
		self.output.Clear()
		self.output.AppendText( dest )
		
	def OnRsaDecode(self,e):
		text = self.rsaEdit.GetValue()
		if text == '':
			return
		
		dest = rsaDecode( text )
		self.output.Clear()
		self.output.WriteText( gbk(dest) )
	
	
	#初始化组件
	def InitComp(self,panel):	
		space = wx.StaticText( panel,-1,'  ' ,size=(20,-1))
		f = wx.Font(12, wx.ROMAN, wx.NORMAL,wx.BOLD,False)
		self.SetFont(f)
		
		#urlcode
		ullb = wx.StaticText( panel,-1,'URLCode ' ,size=(80,-1))
		self.ulEdit = wx.TextCtrl(panel)
		modes = ['UTF-8','GBK']
		self.codeEdit = wx.ComboBox(panel,-1,'UTF-8',choices=modes,style=wx.CB_DROPDOWN|wx.CB_READONLY)
		ueBtn = wx.Button(panel,label='编解码',size=(45,-1))
		ueBtn.SetToolTip("URLCODE编解码")
		ubox = wx.BoxSizer(wx.HORIZONTAL)
		ubox.Add(ullb,proportion=0,flag=wx.ALIGN_RIGHT|wx.CENTER)
		ubox.Add(self.ulEdit,proportion=1,flag=wx.EXPAND)
		ubox.Add(self.codeEdit,0,wx.ALIGN_CENTER_VERTICAL)
		ubox.Add(ueBtn)
		self.Bind(wx.EVT_BUTTON, self.OnUrlcode, ueBtn)
		
		#base64
		bslb = wx.StaticText( panel,-1,'Base64 ' ,size=(80,-1))
		self.bsEdit = wx.TextCtrl(panel)
		bsBtn = wx.Button(panel,label='编码',size=(45,-1))
		bsdBtn = wx.Button(panel,label='解码',size=(45,-1))
		bhbox = wx.BoxSizer(wx.HORIZONTAL)
		bhbox.Add(bslb,proportion=0,flag=wx.ALIGN_RIGHT|wx.CENTER)
		bhbox.Add(self.bsEdit,proportion=1,flag=wx.EXPAND)
		bhbox.Add(bsBtn)
		bhbox.Add(bsdBtn)
		self.Bind(wx.EVT_BUTTON, self.OnBase64encode, bsBtn)
		self.Bind(wx.EVT_BUTTON, self.OnBase64decode, bsdBtn)
		
		#md5
		md5lb = wx.StaticText( panel,-1,'MD5 ' ,size=(80,-1))
		self.md5Edit = wx.TextCtrl(panel)
		self.keyEdit = wx.TextCtrl(panel,-1,'')
		md5Btn = wx.Button(panel,label='加密',size=(45,-1))
		mhbox = wx.BoxSizer(wx.HORIZONTAL)
		mhbox.Add(md5lb)
		mhbox.Add(self.md5Edit,proportion=1,flag=wx.EXPAND|wx.ALL)
		mhbox.Add(self.keyEdit,proportion=1,flag=wx.EXPAND|wx.ALL,border=5)
		mhbox.Add(md5Btn)
		self.Bind(wx.EVT_BUTTON, self.OnMd5, md5Btn)
		
		#CRC32
		crlb = wx.StaticText( panel,-1,'CRC32 ' ,size=(80,-1))
		self.crEdit = wx.TextCtrl(panel)
		crBtn = wx.Button(panel,label='计算',size=(45,-1))
		crbox = wx.BoxSizer(wx.HORIZONTAL)
		crbox.Add(crlb)
		crbox.Add(self.crEdit,proportion=1,flag=wx.EXPAND)
		crbox.Add(crBtn)
		self.Bind(wx.EVT_BUTTON, self.OnCRC32, crBtn)
		
		#mode
		modes = ['ECB','CBC','CFB','OFB']
		mdlb = wx.StaticText( panel,-1,'加密模式 ' ,size=(80,-1))
		self.dsAgEdit = wx.ComboBox(panel,-1,'ECB',choices=modes,style=wx.CB_DROPDOWN|wx.CB_READONLY)
		
		hexlb = wx.StaticText( panel,-1,' 16进制字串 ', style=wx.ALIGN_CENTER, size=(90,-1))
		self.hexEdit = wx.TextCtrl(panel,-1,'',size=(180,-1))
		hexBtn =wx.Button(panel,label='解析',size=(45,-1))
		self.Bind(wx.EVT_BUTTON, self.OnHex,hexBtn)
		mdbox = wx.BoxSizer(wx.HORIZONTAL)
		mdbox.Add(mdlb, 0, wx.ALIGN_CENTER_VERTICAL)
		mdbox.Add(self.dsAgEdit,0,wx.ALIGN_CENTER_VERTICAL, border=5)
		mdbox.Add(space)
		mdbox.Add(hexlb, 0, wx.ALIGN_CENTER_VERTICAL)
		mdbox.Add(self.hexEdit,proportion=1,flag=wx.EXPAND)
		mdbox.Add(hexBtn)
		
		#rc4
		rc4lb = wx.StaticText( panel,-1,'RC4 ' ,size=(80,-1))
		self.rcEdit = wx.TextCtrl(panel,-1,'')
		self.rcEdit.SetHint('内容')
		self.rcKeyEdit = wx.TextCtrl(panel, -1, '')
		self.rcKeyEdit.SetMaxLength(8)
		rcBtn = wx.Button(panel,label='加密',size=(45,-1))
		rcdBtn = wx.Button(panel,label='解密',size=(45,-1))
		rcbox = wx.BoxSizer(wx.HORIZONTAL)
		rcbox.Add(rc4lb)
		rcbox.Add(self.rcEdit,proportion=1,flag=wx.EXPAND)
		rcbox.Add(self.rcKeyEdit,proportion=1,flag=wx.EXPAND)
		rcbox.Add(rcBtn)
		rcbox.Add(rcdBtn)
		self.Bind(wx.EVT_BUTTON, self.OnRC4encode, rcBtn)
		self.Bind(wx.EVT_BUTTON, self.OnRC4decode, rcdBtn)
		
		#des
		dslb = wx.StaticText( panel,-1,'DES ' ,size=(80,-1))
		self.dsEdit = wx.TextCtrl(panel,-1,'')
		self.dsEdit.SetHint('内容')
		self.dsKeyEdit = wx.TextCtrl(panel,-1,'key')
		self.dsKeyEdit.SetMaxLength(8)
		self.dsivEdit = wx.TextCtrl(panel,-1,'')
		self.dsivEdit.SetMaxLength(8)
		self.dsivEdit.SetHint('向量')
		self.dsKeyEdit.SetToolTip('DES密钥必须为8字节长度')
		dsBtn = wx.Button(panel,label='加密',size=(45,-1))
		dsdBtn = wx.Button(panel,label='解密',size=(45,-1))
		dsbox = wx.BoxSizer(wx.HORIZONTAL)
		dsbox.Add(dslb)
		dsbox.Add(self.dsEdit,proportion=1,flag=wx.EXPAND)
		dsbox.Add(self.dsKeyEdit,proportion=1,flag=wx.EXPAND)
		dsbox.Add(self.dsivEdit,proportion=1,flag=wx.EXPAND)
		dsbox.Add(dsBtn)
		dsbox.Add(dsdBtn)
		self.Bind(wx.EVT_BUTTON, self.OnDesencode, dsBtn)
		self.Bind(wx.EVT_BUTTON, self.OnDesdecode, dsdBtn)
		
		#3des
		d3lb = wx.StaticText( panel,-1,'3DES ' ,size=(80,-1))
		self.d3Edit = wx.TextCtrl(panel)
		self.d3KeyEdit = wx.TextCtrl(panel)
		self.d3ivEdit = wx.TextCtrl(panel,-1,'')
		self.d3ivEdit.SetMaxLength(24)
		self.d3KeyEdit.SetToolTip('DES3密钥必须为16或24字节长度')
		d3Btn = wx.Button(panel,label='加密',size=(45,-1))
		d3dBtn = wx.Button(panel,label='解密',size=(45,-1))
		d3box = wx.BoxSizer(wx.HORIZONTAL)
		d3box.Add(d3lb)
		d3box.Add(self.d3Edit,proportion=1,flag=wx.EXPAND)
		d3box.Add(self.d3KeyEdit,proportion=1,flag=wx.EXPAND)
		d3box.Add(self.d3ivEdit,proportion=1,flag=wx.EXPAND)
		d3box.Add(d3Btn)
		d3box.Add(d3dBtn)
		self.Bind(wx.EVT_BUTTON, self.OnDes3encode, d3Btn)
		self.Bind(wx.EVT_BUTTON, self.OnDes3decode, d3dBtn)
		
		#aes
		aslb = wx.StaticText( panel,-1,'AES ' ,size=(80,-1))
		self.asEdit = wx.TextCtrl(panel)
		self.asKeyEdit = wx.TextCtrl(panel,-1,'')
		self.asKeyEdit.SetMaxLength(32)
		self.asivEdit = wx.TextCtrl(panel,-1,'')
		self.asivEdit.SetMaxLength(16)
		self.asKeyEdit.SetToolTip('AES密钥必须为16, 24, 或者32字节长度')
		asBtn = wx.Button(panel,label='加密',size=(45,-1))
		asdBtn = wx.Button(panel,label='解密',size=(45,-1))
		asbox = wx.BoxSizer(wx.HORIZONTAL)
		asbox.Add(aslb)
		asbox.Add(self.asEdit,proportion=1,flag=wx.EXPAND)
		asbox.Add(self.asKeyEdit,proportion=1,flag=wx.EXPAND)
		asbox.Add(self.asivEdit,proportion=1,flag=wx.EXPAND)
		asbox.Add(asBtn)
		asbox.Add(asdBtn)
		self.Bind(wx.EVT_BUTTON, self.OnAesencode, asBtn)
		self.Bind(wx.EVT_BUTTON, self.OnAesdecode, asdBtn)
		
		#sha
		shlb = wx.StaticText( panel,-1,'SHA ' ,size=(80,-1))
		self.shEdit = wx.TextCtrl(panel)
		shBtn = wx.Button(panel,label='加密',size=(45,-1))
		shbox = wx.BoxSizer(wx.HORIZONTAL)
		shbox.Add(shlb)
		shbox.Add(self.shEdit,proportion=1,flag=wx.EXPAND)
		shbox.Add(shBtn)
		self.Bind(wx.EVT_BUTTON, self.OnSha, shBtn)
				
		#rsa
		rsalb = wx.StaticText( panel,-1,'RSA ' ,size=(80,-1))
		self.rsaEdit = wx.TextCtrl(panel)
		rsanewBtn = wx.Button(panel,label='生成密钥',size=(70,-1))
		rsaeBtn = wx.Button(panel,label='加密',size=(45,-1))
		rsadBtn = wx.Button(panel,label='解密',size=(45,-1))
		rsbox = wx.BoxSizer(wx.HORIZONTAL)
		rsbox.Add(rsalb)
		rsbox.Add(self.rsaEdit,proportion=1,flag=wx.EXPAND)
		rsbox.Add(rsanewBtn)
		rsbox.Add(rsaeBtn)
		rsbox.Add(rsadBtn)
		self.Bind(wx.EVT_BUTTON, self.OnNewKey, rsanewBtn)
		self.Bind(wx.EVT_BUTTON, self.OnRsaEncode, rsaeBtn)
		self.Bind(wx.EVT_BUTTON, self.OnRsaDecode, rsadBtn)

		#输出窗口
		box = wx.StaticBox(panel, -1, "输出")
		box.SetForegroundColour(wx.BLUE)
		self.output = wx.TextCtrl(panel,style=wx.TE_MULTILINE|wx.TE_RICH2|wx.TE_READONLY|wx.VSCROLL,size=(200,200)) 
		f = wx.Font(12, wx.ROMAN, wx.ITALIC, wx.BOLD,False)
		self.output.SetFont(f)
		self.output.SetForegroundColour(wx.RED)
		#self.output.SetBackgroundColour(wx.BLACK)
		
		bsizer = wx.StaticBoxSizer(box,wx.VERTICAL)
		bsizer.Add(self.output,1,wx.EXPAND|wx.ALL)
		
		#整体布局
		vbox = wx.BoxSizer(wx.VERTICAL)
		vbox.Add(ubox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(bhbox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(crbox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(mhbox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(shbox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(rsbox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(mdbox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(rcbox, proportion=0, flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(dsbox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(d3box,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(asbox,proportion=0,flag=wx.EXPAND|wx.ALL,border=5)
		vbox.Add(bsizer,proportion=1,flag=wx.EXPAND|wx.ALL,border=5)
		panel.SetSizer(vbox)
	
	#建立菜单栏	
	def setupMenuBar(self):
		self.CreateStatusBar()
	  
		menubar = wx.MenuBar()
		menufile = wx.Menu()
	  
		#使用图片
		im = wx.Bitmap('images/about.png',wx.BITMAP_TYPE_PNG)
		aboutMn = wx.MenuItem(menufile,wx.ID_ABOUT, '关于')
		aboutMn.SetBitmap(im)
		menufile.Append(aboutMn)
		
		qtIm = wx.Bitmap('images/quit.png',wx.BITMAP_TYPE_PNG)
		mnuexit = wx.MenuItem(menufile,wx.ID_EXIT, '退出', '退出本程序')
		mnuexit.SetBitmap(qtIm)
		menufile.Append(mnuexit)
		
		menubar.Append(menufile, '帮助')
		self.SetMenuBar(menubar)
	  
		#事件绑定
		self.Bind(wx.EVT_MENU, self.OnAbout, aboutMn)
		self.Bind(wx.EVT_MENU, self.OnExit, mnuexit)
		  
	
	def OnAbout(self,e):
		info = wx.adv.AboutDialogInfo()
		info.SetName( '工具箱' )
		info.SetIcon(wx.Icon('images/elephant.png',wx.BITMAP_TYPE_PNG)) 
		info.SetVersion('2.0') 
		info.SetDescription('Python 版加解密工具箱') 
		info.SetCopyright('(C) 2015 - 2017 Kettas') 
		info.SetWebSite('http://tcspecial.iteye.com') 
		wx.adv.AboutBox(info) 
		
	def OnExit(self, e):
	  self.Close(True)
	  
#main	 
if __name__=='__main__':  
	reload(sys)  
	sys.setdefaultencoding('utf-8')
	
	app = wx.App()
	
	win = Toolpad(None,title="加解密工具箱")
	win.Show()
	
	app.MainLoop()

