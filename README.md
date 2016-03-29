# cross-cert-gen
----

## About

cross-cert-genは、クロス証明書の生成ツールです。

任意の証明書を、別のCA証明書・秘密鍵で再署名します。  
生成される証明書に、openssl.cnfに従いx509v3拡張を追加することができます。  
再署名する証明書の秘密鍵は必要ありません。

管理外のオレオレルートCA証明書を自組織のルート認証局配下に組み入れ、  
「x509v3 Name Constraints」により発行する証明書の名前空間を制限することが出来ます。


## WARNING

本ツールは、検証を目的としたサンプル実装です。正しく動作する保証はありません。  
再署名した証明書による認証やx509v3拡張が正しく動作するかは、OSやSSL実装に依存します。


## Build

ビルドには、libcrypto(OpenSSL)が必要です。

```
$ make
```


## Usage

```
cross-cert-gen TARGET_CERT CA_CERT CA_KEY OPENSSL_CONF OUT_CERT
  TARGET_CERT   : 再署名する証明書
  CA_CERT       : 署名に使用するCA証明書
  CA_KEY        : 署名に使用するCA秘密鍵
  OPENSSL_CONF  : 付与するx509v3拡張を記載したopenssl.cnf
  OUT_CERT      : 再署名した証明書の保存先
```

入力ファイル(各証明書・秘密鍵)はPEMフォーマットである必要があります。


## Auther

 - Hiroshi KIHIRA

