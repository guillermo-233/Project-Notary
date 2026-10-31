# Documento de Diseño: Arquitectura y Decisiones Técnicas

A continuación, se justifican las decisiones de diseño adoptadas en la implementación de la herramienta de firma `notary.py`, respondiendo a las cuestiones arquitectónicas clave del estándar CAdES/CMS:

### 1. Diferenciación de los certificados del DNIe
**El DNIe tiene dos certificados. ¿Cuál debe firmar un documento y cómo los distingue el programa sin depender de sus etiquetas?** 
El certificado que se debe utilizar para firmar documentos legales o vinculantes es el Certificado de Firma (y no el de Autenticación). Para distinguirlos a nivel programático sin depender del texto de la etiqueta (que podría variar), el programa inspecciona la extensión *Key Usage* (Uso de la clave) definida en el estándar X.509. El certificado correcto es aquel que tiene activado el bit de `non_repudiation` (No repudio / Compromiso de contenido). El certificado de autenticación carece de este bit (suele tener solo `digital_signature` o `key_agreement`).

### 2. Sellado de Tiempo (TSA)
**¿Qué se envía exactamente a la TSA? ¿Por qué no el documento? ¿Qué probaría un sello sobre el documento y qué no probaría?** 
A la TSA se le envía el hash SHA-256 del valor de la firma criptográfica RSA (`signature_bytes`), no el hash del documento original. Si enviáramos el documento a la TSA, el sello resultante únicamente probaría que el documento existía en ese momento en el tiempo (Proof of Existence). Sin embargo, no probaría en absoluto cuándo fue firmado por el usuario. Al aplicar el sello de tiempo sobre la firma matemática, demostramos criptográficamente que la firma ya había sido calculada y existía en ese instante preciso, vinculando la identidad del firmante con la fecha de la acción.

### 3. Los bytes reales que firma la tarjeta inteligente
**¿Qué bytes firma realmente la tarjeta?** 
La tarjeta no firma el documento directamente. La tarjeta firma el hash de la estructura `SignedAttributes` codificada en DER. Sin embargo, en el estándar CMS, para calcular esta firma, los atributos no se codifican exactamente como aparecen en el archivo final (que es una secuencia/lista), sino que se deben empaquetar forzosamente como un conjunto ordenado (`SET OF`). Esto implica que los bytes que se envían al DNIe para firmar siempre comienzan con la etiqueta ASN.1 de SET (0x31), seguida de la longitud y el contenido codificado de los atributos (que incluyen el hash del documento, el tipo de contenido, la fecha local y el hash del certificado).

### 4. Propósito de signingCertificateV2
**¿Por qué está ahí signingCertificateV2? ¿Qué ataque previene?** 
El atributo `signingCertificateV2` incluye el hash criptográfico del certificado utilizado para firmar, y se incluye dentro de los atributos que van a ser firmados por la tarjeta. Esto previene un ataque de sustitución de certificados. Sin este atributo, un atacante podría intentar buscar o emitir un certificado diferente que tuviera la misma clave pública o que generara una colisión matemática con la firma, intentando atribuir la firma a otra identidad o evadir responsabilidades. Al incluir el hash del certificado en los datos sellados, se crea un vínculo irrompible entre la firma y ese certificado específico.

### 5. Cadena de Confianza
**El archivo de firma contiene certificados. ¿Puede tu verificador confiar en ellos? ¿De dónde viene la confianza?** 
No, el verificador nunca debe confiar ciegamente en los certificados simplemente porque vengan adjuntos en el archivo `.csig`. Un atacante podría adjuntar un certificado falso generado por él mismo. La confianza se deriva de un *Trust Anchor* (Ancla de confianza), que es un certificado raíz de una Autoridad de Certificación (CA) preconfigurada y segura en el sistema del verificador (proporcionada en nuestro programa mediante el parámetro `--trust`). El verificador debe comprobar matemáticamente que el certificado adjunto en el archivo fue emitido (firmado) por esa CA de confianza.

### 6. Discrepancia temporal: TSA vs signingTime
**La TSA dice 10:42 y signingTime dice 11:42. ¿Cuál gana, y por qué podrían diferir por una hora o por tres años?** 
El tiempo dictado por la TSA siempre gana.
El atributo `signingTime` es una simple reclamación o afirmación (*claim*) introducida por el reloj del ordenador local del firmante. Puede diferir por una hora debido a un desajuste de zonas horarias (Timezones) o al horario de verano, o por tres años si el reloj del ordenador está manipulado o tiene la pila gastada.
La TSA, por el contrario, es una Autoridad de Sellado de Tiempo de Tercera Parte Confiable que utiliza fuentes de tiempo auditadas (como relojes atómicos o GPS) y sella criptográficamente esa marca. Es la única prueba temporal irrefutable en un juicio.

### 7. Revocación de certificados y validación
**Un certificado es revocado hoy. ¿Era válida una firma realizada el mes pasado? ¿Qué información necesitarías para responder, y el OCSP te la da?** 
Sí, una firma realizada el mes pasado es perfectamente válida si podemos demostrar que en el instante exacto en que se firmó, el certificado estaba activo y no había sido revocado. Un servicio OCSP estándar, al consultarlo de forma normal, solo devuelve el estado de revocación en el momento actual ("hoy está revocado"). Para probar que la firma de hace un mes era válida, necesitamos información histórica: un sello de tiempo confiable (TSA) de hace un mes, combinado con una respuesta OCSP o CRL que fuera válida en ese momento (Validación a Largo Plazo - LTV). Si el archivo `.csig` incrustó la respuesta OCSP en el momento de la firma junto con la TSA, podemos verificarlo offline hoy y considerarlo válido.

### 8. Garantías del Timestamp
**¿Qué prueba tu sello de tiempo sobre el momento de la firma? ¿Podría haberse hecho antes? ¿Alguien más podría haberla hecho con tu tarjeta?**
*   El sello de tiempo prueba que la firma existía antes o en el instante exacto en que la TSA emitió el sello. No se puede sellar algo que aún no se ha creado.
*   Sin embargo, sí podría haberse hecho antes: un usuario podría firmar un archivo offline con su DNIe el lunes, guardar el resultado en un pendrive, y enviarlo a la TSA el viernes. La TSA probaría que la firma existía el viernes, estableciendo un límite temporal máximo, pero no mínimo.
*   Nadie más podría haber hecho la firma porque la clave privada nunca abandona la tarjeta. Para generar la operación matemática, es imprescindible tener posesión física de la tarjeta y conocimiento del secreto mental (el PIN). Si el PIN se mantiene en secreto, la firma es garantía absoluta de autoría (principio de No Repudio).

### 9. Formatos
El programa gestiona firmas digitales, las cuales soportan el no repudio, la autenticación y pueden ser validadas por una tercera parte de forma independiente. Para trabajar con las identidades, se procesan certificados de clave pública que unen las propiedades de un sujeto a una clave pública concreta. Respecto a los contenedores de estos certificados, existen varios formatos estándar, como PKCS12 (que funciona como un contenedor cifrado) y PEM (que es un contenedor sin cifrar). El diseño de la herramienta admite certificados en formato PEM para la ejecución de firmas por software, mientras que internamente y para el empaquetado final del archivo (`.csig`) se utiliza codificación binaria DER bajo la estructura CMS/CAdES.

### 10. Cómo la verificación decide cada veredicto
El proceso de verificación evalúa las evidencias matemáticas y temporales paso a paso para emitir uno de los siguientes resultados:
*   **VALID:** Se emite cuando se cumplen todos los requisitos de seguridad. El hash del documento original coincide con el atributo firmado, la validación matemática RSA de la firma es exitosa, el sello de tiempo (TSA) coincide exactamente con la firma, y el certificado estaba vigente. Además, la cadena de confianza debe completarse con éxito: el verificador comprueba matemáticamente que el certificado adjunto fue firmado por una CA de confianza, ya que se necesita la clave pública de la CA para verificar el certificado del firmante.
*   **INVALID:** Se determina si falla cualquier pilar de la integridad o confianza. Esto incluye la alteración del documento (los hashes no coinciden), una firma matemática RSA incorrecta, el uso de un certificado caducado, o la incapacidad de trazar la cadena de confianza hasta la CA raíz. También será inválido si el sello de tiempo se calculó sobre una firma diferente.
*   **INDETERMINATE:** Se arroja cuando la criptografía es matemáticamente correcta, pero faltan evidencias de terceros para garantizar la validez en el tiempo. Ocurre si la firma carece de un sello de una TSA (dependiendo únicamente del atributo `signingTime` local, que es manipulable). También ocurre si se evalúa una firma en el futuro y no se dispone de una respuesta OCSP histórica (LTV) incrustada en el contenedor para demostrar de forma offline que el certificado era válido el mes pasado.

### 11. Limitaciones conocidas
*   **Incertidumbre del límite temporal inferior:** Aunque la TSA garantiza de forma irrefutable que la firma existía en el instante en que se emitió el sello, un usuario podría realizar la firma offline y enviarla a la TSA días después; el sello establece el límite temporal máximo, pero no el mínimo.
*   **Uso estricto de certificados:** No todos los certificados valen para todo. La herramienta impone un filtro estricto y exige que el certificado del DNIe tenga activado el bit de `non_repudiation` (No repudio), lo que impide firmar accidentalmente con certificados destinados puramente a la autenticación o cifrado.
*   **Dependencia de conectividad para el archivo a largo plazo:** Para que el documento sea robusto ante futuras revocaciones de certificados (Validación a Largo Plazo - LTV), el programa depende absolutamente de tener conexión a Internet en el momento de la firma para contactar con los servidores de la TSA y recuperar el estado OCSP. Si estos fallan, la firma seguirá siendo criptográficamente válida en el presente, pero no incrustará las pruebas necesarias para el futuro.