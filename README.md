# -Buffer-Overflow-

Representacion grafica de que es lo que pasa cuando se genera un BoF

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/98bf083c-df68-4159-be95-a1fa29715c99)


El Define una serie de pasos lo cual me parece bien para hacer esto ordenado

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/b06f1f2e-9796-4e70-a11f-fa9542521428)

## Spike (generic_send_tcp)

When you need to analyze a new network protocol for buffer overflows or similar weaknesses, the SPIKE is the tool of choice for professionals. While it requires a strong knowledge of C to use, it produces results second to none in the field. (ojo tiene muchas herramientas no solo generic send)

```
sudo apt install spike
```
> https://www.kali.org/tools/spike/

Y el modo de uso es:

```bash
# La ip sera del vuln server

./generic_send_tcp host port spike_script SKIPVAR SKIPSTR

./generic_send_tcp 192.168.0.100 999 something.spk 0 0

```

El script en spike que el escribio es el siguiente 

![image](https://github.com/gecr07/-Buffer-Overflow-/assets/63270579/bbafb67f-1e2e-42c1-bce9-c1e62fb56a50)
























