# AES CBC
Implementation of the AES CBC method in several languages to share information between compilers.

## Encryption by language
Java
```sh
iv: [-13, -49, -22, 88, -51, 109, 12, -21, 20, -20, 24, 88, 91, 21, -48, 31]
88/qWM1tDOsU7BhYWxXQH/jTt9fD17ryDSFuGk6YlPY=
```

C#
```sh
iv: [188, 59, 243, 63, 125, 152, 65, 179, 97, 72, 218, 97, 51, 187, 154, 179]
vDvzP32YQbNhSNphM7uas95lMVR0vUs2vJCfEQaDzMo=
```

NodeJs
```sh
iv: [250, 112, 233, 163, 176, 147, 17, 251, 28, 236, 141, 222, 57, 203, 85, 52]
+nDpo7CTEfsc7I3eOctVNKM57Ai++DzzOlwohKaMU8c=
```

## Decryption by language generated by other languages

Java
```sh
Java
iv: [-13, -49, -22, 88, -51, 109, 12, -21, 20, -20, 24, 88, 91, 21, -48, 31]
Message
----
C#
iv: [-68, 59, -13, 63, 125, -104, 65, -77, 97, 72, -38, 97, 51, -69, -102, -77]
Message
----
NodeJs
iv: [-6, 112, -23, -93, -80, -109, 17, -5, 28, -20, -115, -34, 57, -53, 85, 52]
Message
```

C#
```sh
Java
iv: [243, 207, 234, 88, 205, 109, 12, 235, 20, 236, 24, 88, 91, 21, 208, 31]
Message
----
C#
iv: [188, 59, 243, 63, 125, 152, 65, 179, 97, 72, 218, 97, 51, 187, 154, 179]
Message
----
NodeJs
iv: [250, 112, 233, 163, 176, 147, 17, 251, 28, 236, 141, 222, 57, 203, 85, 52]
Message
```

NodeJs
```sh
Java
iv: [243, 207, 234, 88, 205, 109, 12, 235, 20, 236, 24, 88, 91, 21, 208, 31]
Message
----
C#
iv: [188, 59, 243, 63, 125, 152, 65, 179, 97, 72, 218, 97, 51, 187, 154, 179]
Message
----
NodeJs
iv: [250, 112, 233, 163, 176, 147, 17, 251, 28, 236, 141, 222, 57, 203, 85, 52]
Message
```