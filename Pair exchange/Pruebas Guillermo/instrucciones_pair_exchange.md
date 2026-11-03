# Instrucciones para el Pair Exchange

¡Hola! Aquí tienes mi set de 6 pruebas criptográficas generadas con `notary.py` para la fase de Pair Exchange. 

He incluido tanto firmas legítimas como firmas defectuosas. Tu objetivo es pasar tu verificador por todas ellas y comprobar si detecta correctamente cuáles son válidas y cuáles fallan (y por qué).

## Archivos que te adjunto en el ZIP:

**Documentos originales:**
* `contrato.txt`
* `nota.txt`
* `importante.txt`
* `archivo4.txt`
* `documento6.txt`

**Pruebas de firma:**
* `prueba1_valida.csig`
* `prueba2_valida.csig`
* `prueba3_modificada.csig`
* `prueba4_trust.csig`
* `prueba5_malformada.csig`
* `prueba6_tsa_falsa.csig`

**Ancla de confianza de software:**
* `cert_prueba.pem` (Mi certificado público para que lo uses en el parámetro `--trust` en las firmas por software).

---

## Comandos para ejecutar las pruebas

Para asegurarnos de que usas el ancla de confianza correcta en cada caso, te dejo aquí los comandos exactos que debes ejecutar en tu terminal con tu verificador (`notary.py`). 

*(Nota: Asegúrate de tener a mano el certificado raíz de la Policía Nacional, por ejemplo `ACRaiz2.crt`, para verificar la prueba del DNIe).*

### Prueba 1
Firma realizada con DNIe. Usa el certificado de la Policía como ancla de confianza.
```bash
python notary.py verify prueba1_valida.csig --content contrato.txt --trust ac_dnie.crt
```

### Prueba 2
Firma realizada por software. Usa mi certificado público adjunto.
```bash
python notary.py verify prueba2_valida.csig --content nota.txt --trust cert_prueba.pem
```

### Prueba 3
Firma realizada por software.
```bash
python notary.py verify prueba3_modificada.csig --content importante.txt --trust cert_prueba.pem
```

### Prueba 4
Firma realizada por software. Sin embargo, para esta prueba en concreto, **te pido que la verifiques contra el certificado de la Policía** en lugar de mi certificado de software.
```bash
python notary.py verify prueba4_trust.csig --content archivo4.txt --trust ac_dnie.crt
```

### Prueba 5
Firma basada en DNIe.
```bash
python notary.py verify prueba5_malformada.csig --content contrato.txt --trust ac_dnie.crt
```

### Prueba 6
Firma realizada por software.
```bash
python notary.py verify prueba6_tsa_falsa.csig --content documento6.txt --trust cert_prueba.pem
```

---
¡Suerte analizando las firmas! Cuando termines, pásame tus resultados para que podamos comparar nuestros veredictos.