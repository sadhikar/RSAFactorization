from Crypto.PublicKey import RSA
import sys
import pyasn1.codec.der.encoder
import pyasn1.type.univ
import base64
import timeit
import time
from colorama import Fore, Style, Back

# Function to mint a private key file once you have the private key "d" in RSA.
def pempriv(n, e, d, p, q, dP, dQ, qInv):
 template = '-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n'
 seq = pyasn1.type.univ.Sequence()
 for x in [0, n, e, d, p, q, dP, dQ, qInv]:
 	seq.setComponentByPosition(len(seq), pyasn1.type.univ.Integer(x))
 der = pyasn1.codec.der.encoder.encode(seq)
 return template.format(base64.encodestring(der).decode('ascii'))

# Function to find Greatest Common divisor(GCD) for two numbers.
def gcd(a, b): return gcd(b, a % b) if b else a

# Function to evaluate extended GCD for two given numbers, in turn used in modulo inverse
def egcd(a, b):
     if a == 0:
         return (b, 0, 1)
     else:
         g, y, x = egcd(b % a, a)
         return (g, x - (b // a) * y, y)

# Function to find modulo inverse for a given value 
def modinv(a, m):
     gcd, x, y = egcd(a, m)
     if gcd != 1:
         return None  # modular inverse does not exist
     else:
         return x % m


#read the path for the keys from command line args
if len(sys.argv) < 2:
 print "format to run this script: python factorize.py <path for keys>"
 sys.exit(0)
path = sys.argv[1]

# Arrays to handle the pem file and respective public keys.
pem = [0]*100
k = [0]*100


print "Reading 100 RSA public key files... "
time.sleep(2)
for x in range (1,100):
 pem[x] = open(path+str(x)+".pem").read()

print "\nExtracting the 100 RSA public keys for analysis..."
time.sleep(2)
for x in range (1,100):
 k[x] = RSA.importKey(pem[x])


collidingKeys = {}


print "Running analysis on N for the 100 public keys, looking for common prime factors..."
time.sleep(2)
print (Fore.RED+"\n\nBad randomness while key generation has lead to multiple keys with common factors.")
time.sleep(2)
print(Style.RESET_ALL)
print "\nKey sets with common factors:"
time.sleep(2)
for x in range (1,100):
 for y in range (x+1,100): 	
  if gcd(k[x].n,k[y].n) <> 1: 
    collidingKeys[x] = gcd(k[x].n,k[y].n)
    collidingKeys[y] = gcd(k[x].n,k[y].n)
    print str("\n\n"+str(x)+".pem and "+str(y)+".pem")
    print "\n Common factor= "+str(gcd(k[x].n,k[y].n))

e = 0x10001L

time.sleep(2)
print (Fore.GREEN+"\nUsing the common factor evaluating the respective private keys d...")
time.sleep(2)
print (Fore.GREEN+"\n\nMinting respective RSA private key files...")
start_time = timeit.default_timer()
for x,val in collidingKeys.iteritems():
  p = int(val)
  n = k[x].n	
  q = k[x].n/p
  tot = (p-1)*(q-1)
  d = modinv(e,tot)
  dp = d % p
  dq = d % q
  qi = pow(q,p-2,p)
  key = pempriv(n,e,d,p,q,dp,dq,qi)
  f = open("recovered_key"+str(x)+".key","w")	
  f.write(key)
  f.close
elapsed = timeit.default_timer() - start_time
print"\n\nMinting successful.\nTotal time taken for minting "+ str(len(collidingKeys))+" keys is "+str(elapsed)










