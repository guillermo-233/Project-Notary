# Qué demuestra un sello de tiempo (What a timestamp proves)

En el contexto de las firmas digitales avanzadas (como el formato CAdES-T implementado en este proyecto), el sello de tiempo o *Time Stamp Token* (RFC 3161) emitido por una Autoridad de Sellado de Tiempo (TSA) es la piedra angular para garantizar la integridad temporal de un documento electrónico. Sin embargo, es crucial entender los límites exactos de esta garantía criptográfica.

## Lo que SÍ demuestra el sello de tiempo

El sello de tiempo demuestra irrefutablemente **la existencia de la firma en un instante de tiempo específico (o anterior)**. 

En la arquitectura CAdES-T, la petición a la TSA no se realiza enviando el hash del documento original, sino enviando el hash del **valor de la firma criptográfica RSA** ya calculada. Puesto que es matemáticamente imposible predecir o falsificar una firma RSA, y la TSA firma criptográficamente la respuesta uniendo ese hash a la hora oficial de sus servidores seguros, obtenemos una prueba matemática absoluta: la firma tuvo que ser generada, por fuerza, **antes o en el mismo segundo** en que la TSA emitió su sello.

Esto establece un **límite temporal superior** robusto y legalmente vinculante. Demuestra que la firma no pudo haber sido creada *después* de la fecha y hora indicadas por la TSA. Esto es vital para verificar, por ejemplo, si el certificado del firmante (DNIe) estaba activo y no revocado en el momento en que se selló la operación (Validación a Largo Plazo).

## Lo que NO demuestra el sello de tiempo

Por el contrario, el sello de tiempo **no demuestra el momento exacto** en el que el usuario ejecutó la acción de firmar (el límite temporal inferior). 

Dado que el proceso de firma (operación en el DNIe) y el proceso de sellado (petición de red a la TSA) están desacoplados, existe una ventana de tiempo indeterminada entre ambos. Un usuario podría, teóricamente:
1. Firmar un documento en un ordenador sin conexión a Internet un lunes.
2. Guardar los datos de la firma en un pendrive.
3. Conectarse a Internet el viernes y enviar el hash de esa firma a la TSA para obtener el sello.

En este escenario, el sello de tiempo certificaría que la firma existía el viernes. No hay ninguna forma técnica de que el verificador sepa que la acción humana (introducir el PIN en la tarjeta) ocurrió cuatro días antes. Por lo tanto, el sello garantiza un *"no más tarde de"*, pero nunca un *"exactamente en"*.

Finalmente, tampoco se debe confundir la hora de la TSA con el atributo `signingTime` presente en los atributos firmados (`SignedAttributes`). El `signingTime` es una simple afirmación local basada en el reloj del ordenador del usuario, el cual puede ser fácilmente manipulado o tener la pila agotada. Por ello, carece de validez probatoria frente a la hora inyectada por la TSA.