
export type KeyByType<Type> =
  Type extends 'RSA' ? import('./rsa-class').PrivateKey :
    Type extends 'ED25519' ? import('./ed25519-class').PrivateKey :
      Type extends 'secp256k1' ? import('./secp256k1-class').PrivateKey :
        never
