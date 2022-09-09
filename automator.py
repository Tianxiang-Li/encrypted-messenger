from encrypted_package_pb2 import IM

def hmac_verification_passed():
    print( "The HMAC was verified." )

def hmac_verification_failed():
    print( "The HMAC failed to verify.")

def decrypted_IM( im ):
    print( "(%s,%s)" % (im.nickname, im.message) )
