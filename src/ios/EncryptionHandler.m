//
//  EncryptionHandler.m
//  Moodle
//
//  Created by Alex Morris on 18/01/23.
//

#import "EncryptionHandler.h"

@implementation EncryptionHandler

+ (NSString*) decrypt:(NSString *)ciphertext {
    NSData* tag = [[[NSBundle mainBundle] bundleIdentifier] dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* getQuery = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
        (id)kSecReturnRef: @YES,
    };

    SecKeyRef privateKey = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getQuery,
                                          (CFTypeRef*)&privateKey);

    NSString* cleartext = NULL;

    if (status != errSecSuccess) {
        NSLog(@"PushPlugin private key not found!");
        return cleartext;
    }

    // Use key
    if (privateKey) {
        NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:ciphertext options:0];

        CFErrorRef error = NULL;
        NSData *decryptedData = (__bridge_transfer NSData*)SecKeyCreateDecryptedData(privateKey, kSecKeyAlgorithmRSAEncryptionOAEPSHA256, (CFDataRef)encryptedData, &error);

        if (error != NULL) {
            NSLog(@"PushPlugin error decrypting data!");
        } else {
            cleartext = [[NSString alloc] initWithData:decryptedData encoding:NSASCIIStringEncoding];
        }

        CFRelease(privateKey);
    } else {
        NSLog(@"PushPlugin private key not found!");
    }
    return cleartext;
}

+ (BOOL) keyExists {
    NSData* tag = [[[NSBundle mainBundle] bundleIdentifier] dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* getQuery = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
        (id)kSecReturnRef: @YES,
    };

    SecKeyRef privateKey = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getQuery,
                                          (CFTypeRef*)&privateKey);
    if (status != errSecSuccess) {
        return false;
    }
    // Use key
    if (privateKey) {
        CFRelease(privateKey);
        return true;
    }

    return false;
}

+ (NSString*) getPublicKey {
    if (![EncryptionHandler keyExists]) {
        [EncryptionHandler generateKeyPair];
    }

    NSData* tag = [[[NSBundle mainBundle] bundleIdentifier] dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* getQuery = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
        (id)kSecReturnRef: @YES,
    };

    SecKeyRef privateKey = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getQuery,
                                          (CFTypeRef*)&privateKey);
    if (status != errSecSuccess) {
        return @"PushPlugin Failed to retrieve key";
    }
    // Use key
    if (privateKey) {
        SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);

        CFErrorRef errorRef = NULL;

        CFDataRef keyData = SecKeyCopyExternalRepresentation(publicKey, &errorRef);
        NSData *publicKeyData = (NSData *)CFBridgingRelease(keyData);
        NSString *pkcs1String = [@"-----BEGIN RSA PUBLIC KEY-----\n" stringByAppendingString:[
            [publicKeyData base64EncodedStringWithOptions:0] stringByAppendingString:@"\n-----END RSA PUBLIC KEY-----"]
        ];

        if (errorRef != NULL) {
            NSError* error = (__bridge NSError*)errorRef;
            NSLog(@"PushPlugin error: %@", error);
        }

        CFRelease(publicKey);
        CFRelease(privateKey);

        return pkcs1String;
    }

    return @"PushPlugin Failed to retrieve key";
}

+ (void) generateKeyPair {
    NSData* tag = [[[NSBundle mainBundle] bundleIdentifier] dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary* attributes =
    @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeySizeInBits: @2048,
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrApplicationTag: tag,
        },
    };

    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);

    if (!privateKey) {
        NSError* err = CFBridgingRelease(error);
        NSLog(@"PushPlugin Key Generation error: %@", err);
    }
}

@end
