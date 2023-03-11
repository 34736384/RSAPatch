
# RSAPatch
A patch to get into grass cutting for a certain anime game
 - Updated for 3.5.5x, and above (maybe)
 - Supports older versions as well
## How to Use?

 - Download dll from release or compile it (**as Release**) yourself
 - Rename it to `version.dll` or `mhypbase.dll` and put it in the same folder as the game
 - Create a file named `PublicKey.txt` under the same folder as the game and put your public key in there
 - **Grasscutter's public key is now hardcoded as default, if you only planning it use it with gc, then you don't have to create any additional files**
 - **[Optional]** If you need to replace the private key, create a file named `PrivateKey.txt` under the same folder and put your private key in there
 - Finally start the game, if you done it right, there should be a console window popup
## Infos
 - For Grasscutter, only the public key is needed for now.
 - Tested on 3.1, 3.2, and 3.2.50. It should work for future versions too, unless they have new protections
 - **DO NOT** create `PrivateKey.txt` if you don't need it
 - Public key for Grasscutter: `<RSAKeyValue><Modulus>xbbx2m1feHyrQ7jP+8mtDF/pyYLrJWKWAdEv3wZrOtjOZzeLGPzsmkcgncgoRhX4dT+1itSMR9j9m0/OwsH2UoF6U32LxCOQWQD1AMgIZjAkJeJvFTrtn8fMQ1701CkbaLTVIjRMlTw8kNXvNA/A9UatoiDmi4TFG6mrxTKZpIcTInvPEpkK2A7Qsp1E4skFK8jmysy7uRhMaYHtPTsBvxP0zn3lhKB3W+HTqpneewXWHjCDfL7Nbby91jbz5EKPZXWLuhXIvR1Cu4tiruorwXJxmXaP1HQZonytECNU/UOzP6GNLdq0eFDE4b04Wjp396551G99YiFP2nqHVJ5OMQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>`
