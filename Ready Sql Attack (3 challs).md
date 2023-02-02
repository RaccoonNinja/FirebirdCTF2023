## Skills required: Preseverance, Coppersmith

A hard but fun series of 3 challenges working with limited SQL functionalities.
We got the first and only blood for all 3 challenges, but it's mostly my teammate's idea - I just fleshed out some details and did the brute-forcing.

~~I'm still traumatized by the UwUs. Please help~~

## smol solution (solved by grhkm, fsharp, ymd):

We have to exfiltrate the flag `c` split in **6-character chunks**, whose base29 values are then encoded in textbook RSA.
However the 30-bit `n` changes every request and we can only read the database and carry out recursive(?) queries (we'll go back to this later).
This means no `insert`, `update`, `alter` and definitely not `attach` which is a common vector for file inclusion and RCE for the PHP-Sqlite stack.

```php
// oof, no access to SQL functions. that means no abs(), substr(), random(), ... >_>
$user_connection->setAuthorizer(function (int $action, ...$args) {
    if ($action === SQLite3::SELECT || $action === SQLite3::READ || $action === SQLite3::RECURSIVE) { // OwO what's this?
        return SQLite3::OK;
    } else {
        return SQLite3::DENY;
    }
});
```
The key insight is that we can just *decode the flag in SQL by raising it to 17th power*, as `e` is crucially not 17 but 17's inverse.

```php
$e = gmp_invert(17, $phi); // OwO

$secret_message = $_ENV['FLAG'];
$chunks = str_split($secret_message, 6); // for each 6 chars of the secret message
foreach ($chunks as $chunk) {
    $number = base29StringToNumber($chunk); // convert to a number
    $number = gmp_strval(gmp_powm($number, $e, $n)); // encrypt it and insert into c_table
    $sql = "INSERT INTO c_table (c) VALUES ($number)";
    $db->exec($sql);
}
```

We can just repeatedly square and modulo `n`, but we need to disambiguate between different `c`s.
In *sqlite* by default, there's a [`rowid` column](https://www.sqlite.org/rowidtable.html) that's used internally by the Sqlite engine.

Here's the actual payload:

```py
import requests

payload = '(((((((((((((((((c % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table)) * (c % (SELECT n FROM n_table)) % (SELECT n FROM n_table))'

letters = 'abcdefghijklmnopqrstuvwxyz_{}'
res = []

for d in range(1, 21):
    cur_str = ""
    for k in range(6):
        for i in range(29):
            data = f'SELECT "UwU" FROM c_table WHERE ({payload} / {29 ** k} % 29 = {i}) AND ROWID = {d};'

            data = {
                'query': data,
            }
            # print("Data:", data)

            response = requests.post('http://carbon-chal.firebird.sh:36020/smol.php', data=data)
            resp = response.text.split('\n')[0]
            if "UwU" in resp:
                print(d, k, letters[i])
                cur_str += letters[i]
                break
        else:
            print("Ended")
            break

    print('->', cur_str)
    res.append(cur_str)

print(res)
```

## medium solution (solved by grhkm, RaccoonNinja):

![differences from smol](https://user-images.githubusercontent.com/114584910/216417872-f374689f-e5f2-4663-ac12-38358f54c698.png)

The crucial difference are:
- The power became 101.
- There is a length limit and the trick in smol cannot be used.
- We are now working with 60-bit numbers, which is devastating
  - because the multiplication and squaring operation **overflows 64-bit integer** in Sqlite.

The key insight is that [recursive queries](https://www.sqlite.org/lang_with.html#recursive_query_examples) are basically while-loops in SQLite.
They can do fascinating things like showing hierarchical structures and solving sudokus, pretty crazy stuff.

After appreciating the overflow, our idea was to implement `pow mod n` with recursive queries.
First we need to implement `multiplication mod n` in recursive queries because it overflows as well.

Grhkm tackled this brilliantly (mod n later added):

```sql
WITH RECURSIVE f AS (
    SELECT 28 AS x,
           29 AS y,
           0  AS s
    UNION ALL
    SELECT x * 2 % n, y / 2, (s + (CASE y % 2 WHEN 1 THEN x ELSE 0 END)) % n FROM f JOIN n_table WHERE (y / 2) >= 1
)
SELECT (x + s) % n FROM f WHERE y <= 1;
```

I cleaned it up a little bit, namely I removed the need for the final `x+s` (note that I calculated 6\*6%23 instead of 28\*29%n; I like to work with smaller cases):
```sql
WITH RECURSIVE
  f AS (
      SELECT 6 AS x, 6 AS y, 0 AS s, 0 AS done
      UNION ALL
      SELECT x * 2 % 23, y / 2, (s + (CASE y % 2 WHEN 1 THEN x ELSE 0 END)) % 23, y<=1 FROM f WHERE y >= 0 AND not done
  )
SELECT s FROM f WHERE y <= 1;
```

So we now have a means to calculate square.
We then explored a bit and soon realized that it's not possible to parameterize the recursive query, i.e. *the initial values we give will determine the output*.

This means we need some subroutines[1]: *square-calculating* one and a *multiply-current-square-with-result* one, along with some state to store information.
It took some work but I managed to implement it in 8 variables:

```sql
WITH RECURSIVE
  f AS (
      SELECT 69 AS x, 69 AS y, CASE 420%2 WHEN 1 THEN 69 ELSE 1 END result, 420>>1 AS p, 0 AS s, 0 AS s_backup, 0 AS done, 0 AS square0_mul1
      UNION ALL
      SELECT
        CASE done WHEN 1 THEN s_backup ELSE x * 2 % 65537 END,
        CASE done WHEN 1 THEN (CASE p%2 AND square0_mul1=0 WHEN 1 THEN result else s_backup END) ELSE y>>1 END,
        CASE square0_mul1 AND done WHEN 1 THEN s ELSE result END,
        p>>(done AND square0_mul1=0),
        (1-done)*(s + (CASE y%2 WHEN 1 THEN x ELSE 0 END)) % 65537,
        CASE y=1 and square0_mul1=0 WHEN 1 THEN s + (CASE y%2 WHEN 1 THEN x ELSE 0 END) ELSE s_backup END,
        done=0 and y<=1,
        CASE square0_mul1 WHEN 0 THEN done AND p%2 ELSE done=0 END
      FROM f WHERE p>=1 OR done=0
  )
SELECT s FROM f WHERE p=0 AND done=1;
```

<details>
    <summary>Detailed explanation</summary>

- `x`, `y` are multiplication operands, whose result is stored to `s` (and `sb` for backup)
- `p` is the power
- `sm` is a flag that notates whether the current operation is **s**quaring or **m**ultiplying square with result `r`.
- `d` denotes whether the current operation is done

The program ends with `p==0` and `d`.

```
to calculate 6**5 == 2 mod 23
 x  y  r  p  s sb  d  sm
 6| 6| 6| 2| 0| 0| 0| 0 -- 5 is odd so supply 6 to r(result)
12| 3| 6| 2| 0| 0| 0| 0
 1| 1| 6| 2|12| 0| 0| 0
 2| 0| 6| 2|13|13| 1| 0
!!!!!!!!!!!!!!!!!!!!!!! -- 6**2 == 13 mod 23, don't multiply square to r as 5&2 == 0
13|13| 6| 1| 0|13| 0| 0
...
??| 0| 6| 1| 8| 8| 1| 0
!!!!!!!!!!!!!!!!!!!!!!! -- 6**4 == 18 mod 23, multiply square to r as 5&4 != 0
 6| 8|##| 0| 0| 8| 0| 1
...
??| 0|##| 0| 2| 8| 1| 1
result 2

to calculate 6**10 == 4 mod 23
 x  y  r  p  s sb  d  sm
 6| 6| 1| 5| 0| 0| 0| 0 -- 10 is even so supply 1 to r(result)
...
 2| 0| 1| 5|13| 0| 1| 0
!!!!!!!!!!!!!!!!!!!!!!! -- 10&2 != 0
13| 1| 1| 2| 0|13| 0| 1
...
??| 0|##| 2|13|13| 1| 1
!!!!!!!!!!!!!!!!!!!!!!!
13|13|13| 2| 0|##| 0| 0
...
??| 0|13| 2| 8|##| 1| 0
!!!!!!!!!!!!!!!!!!!!!!! -- 10&4 == 0
 8| 8|13| 1| 0|##| 0| 0
...
??| 0|13| 1|18|##| 1| 0
!!!!!!!!!!!!!!!!!!!!!!! -- 10&8 != 0
13|18|##| 0| 0|##| 0| 1
...
??| 0|##| 0| 4|##| 1| 1
result s=4
```
</details>

The final solve script:

```py
import requests

letters = 'abcdefghijklmnopqrstuvwxyz_{}'
res = []
chunksize = 11
e = 101
base = len(letters)
url = 'http://carbon-chal.firebird.sh:36021/medium.php'

def gen_payload(rowid):
    return f'''WITH RECURSIVE
f AS (
    SELECT c AS x, c AS y, {'c' if e%2 else 1} AS result, {e>>1} AS p, 0 AS s, 0 AS s_backup, 0 AS done, 0 AS square0_mul1 FROM n_table JOIN c_table ON c_table.rowid = {rowid}
    UNION ALL
    SELECT
    CASE done WHEN 1 THEN s_backup ELSE x * 2 % n END,
    CASE done WHEN 1 THEN (CASE p%2 AND square0_mul1=0 WHEN 1 THEN result else s_backup END) ELSE y>>1 END,
    CASE square0_mul1 AND done WHEN 1 THEN s ELSE result END,
    p>>(done AND square0_mul1=0),
    (1-done)*(s + (CASE y%2 WHEN 1 THEN x ELSE 0 END)) % n,
    CASE y=1 and square0_mul1=0 WHEN 1 THEN s + (CASE y%2 WHEN 1 THEN x ELSE 0 END) ELSE s_backup END,
    done=0 and y<=1,
    CASE square0_mul1 WHEN 0 THEN done AND p%2 ELSE done=0 END
    FROM f JOIN n_table ON n_table.rowid = 1 JOIN c_table ON c_table.rowid={rowid} WHERE p>=1 OR done=0
)
'''
# x (60bit)*c(30bit) overflows 64bit
size = len(bin(base**chunksize))-2

def numberToBase(n, b):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return "".join(letters[x] for x in digits[::-1])

for d in range(1, 8):
    cur = 0
    for k in range(size):
        data = f'{gen_payload(d)}SELECT "UwU" FROM (SELECT s FROM f WHERE p=0 AND done=1 AND (s>>{k})%2==1)'
        if d==1 and not k:
            print(data)
        data = {
            'query': data,
        }

        response = requests.post(url, data=data)
        resp = response.text.split('\n')[0]
        if "UwU" in resp:
            cur += 1<<k
    # print(cur)
    print(numberToBase(cur, base))
```

### Official solution

101 is still quite small so repeated squaring is not needed, also we can run 64 times for the multiplication even though the number isn't 64-bit (the upper bits are 0). This allows for really slick codes:

```sql
with recurse(res, a, b, counter) as (\
select 0, 1, c, 0 from (select c from c_table limit 1 offset {}) union all \
select case when counter % 65 = 0 and b % 2 = 0 then 0 \
when counter % 65 = 0 and b % 2 = 1 then a \
when counter % 65 != 0 and b % 2 = 1 then (res + a) % n \
when counter % 65 != 0 and b % 2 = 0 then res end, \
case when counter % 65 = 64 then res else (a * 2) % n end,  \
case when counter % 65 = 64 then c else b / 2 end, \
counter + 1 \
from recurse, n_table, (select c from c_table limit 1 offset {}) where counter < 65 * 101) \
select case when res / {} % 2 = 0 then 'UwU' else ':(' end from recurse limit 1 offset 65 * 101
```

## beeg solution (solved by grhkm, RaccoonNinja, fsharp):

Beeg is a legit crypto challenge instead of misc (I like both).
This cannot be solved without grhkm's rich crypto experience and sage knowledge.

```php
$admin_connection->exec('CREATE TABLE npqc_table (n TEXT, p TEXT, q TEXT, c TEXT)');
// ...
$p = gmp_nextprime(gmp_random_bits(256));
$q = gmp_nextprime(gmp_random_bits(256));
// ...
$c_str = gmp_strval(gmp_powm($plaintext, 0x10001, $n));
// ...
if (isset($_POST['query'])) {
    $query = $_POST['query'];

    if ($query_counter < $max_queries) {
        $result = $user_connection->query($query);
        if ($result && $result->fetchArray()[0] === "UwU") {
            echo "UwU";
        } elseif ($result) {
            echo ":(";
        } else {
            echo "OwO looks like someone tried to be sneaky! Here's a penalty just for you :D";
            $query_counter++;
            $_SESSION['query_counter'] = $query_counter;
        }
        $query_counter++;
        $_SESSION['query_counter'] = $query_counter;
    } else {
        echo "Error: You have reached the maximum number of queries.";
    }
} else {
    echo "Please enter a query to execute.";
}

if (isset($_POST['generate_ciphertext'])) { // no more queries after this :)
    $_SESSION['query_counter'] = $max_queries;
    $query_counter = $max_queries;

    $result = $user_connection->query("SELECT n, c FROM npqc_table");
    list($n, $c) = $result->fetchArray();

    echo "\nYour ciphertext is: \n$c\nAnd your n is:\n $n";
}
```

The crucial difference are:
- `e` is the good ol' `0x10001`.
- `p` and `q` are now 256-bit and along with other values, stored as *string*.
- We can use very simple functions.
- We only have 123 requests:
  - `n` and `c` stay constant and are disclosed when we want it, however we cannot query anything else after this operation.
  - Our SQLs need to return something or we get 1 fewer request (not hard)

Being familiar with Coppersmith, grhkm had a couple of good ideas right away:
- It's insta solve if we can get top or bottom 128-bit of `p` (from Coppersmith)
- We can bruteforce some bits, which should not take long

While ideally we can gain 123-bit information with 123 requests, we can't convert the whole number to binary.
My idea is to **get 3 decimal digits at a time by using 10 requets** (1024>1000). It's the power of 2 closest to a power of 10.
This way we have 12\*3 = 36 digits i.e. `36*log2(10)~=120` bits of info:

```py
for d in range(12):
    cur = 0
    for k in range(10):
        data = {
            'query': f'SELECT CASE (substr(p, {d*3+4}, 3)>>{k})%2 WHEN 1 THEN "UwU" ELSE ":(" END FROM npqc_table;',
        }

        response = s.post(url, data=data)
        resp = response.text.split('\n')[0]
        if "UwU" in resp:
            cur += 1<<k
    # print(cur)
    res+="0"*(3-len(str(cur)))+str(cur)
```

It is still not very enough :') and most importantly the size of `p` is not known.
My initial idea was to use the remaining 3 requests to get `len(p)%8` but grhkm has a better idea: **verify that both p,q are 256-bit and p starts with 111**. It can be done in 1 request (note trickiness of string comparison i.e. "20"<"5"):

```py
best_value = 2**255
max_len = len(str(2**256))
data = {
    'query': f'SELECT CASE (length(p)={max_len} and substr(p,1,3)="111") and (length(q)={max_len} or q>="{best_value}") WHEN 1 THEN "UwU" ELSE ":(" END FROM npqc_table;',
}
```

I interpreted `starting with 111` as **decimal**. While it took more tries, we have **6** bits from this 1 request alone. The remaining 2 requests can be used to get 2 more bits so a total of 128 bits can be obtained.

<details>
    <summary>full info gathering script:</summary>
</details>

```py
import requests
from math import log10

letters = 'abcdefghijklmnopqrstuvwxyz_{}'
e = 0x10001
base = len(letters)
url = 'http://carbon-chal.firebird.sh:36026/beeg.php'

# 256 bits
best_value = 2**255

max_len = len(str(2**256))

while True:
    s = requests.Session()
    data = {
        'query': f'SELECT CASE (length(p)={max_len} and substr(p,1,3)="111") and (length(q)={max_len} or q>="{best_value}") WHEN 1 THEN "UwU" ELSE ":(" END FROM npqc_table;',
    }
    response = s.post(url, data=data)
    resp = response.text.split('\n')[0]
    if "UwU" not in resp:
        print(":(")
        continue
    print("p,q both 256 bit and p starts with 111 yay")
    cur = 0

    res = "111"
    for d in range(12):
        cur = 0
        for k in range(10):
            data = {
                'query': f'SELECT CASE (substr(p, {d*3+4}, 3)>>{k})%2 WHEN 1 THEN "UwU" ELSE ":(" END FROM npqc_table;',
            }

            response = s.post(url, data=data)
            resp = response.text.split('\n')[0]
            if "UwU" in resp:
                cur += 1<<k
        # print(cur)
        res+="0"*(3-len(str(cur)))+str(cur)

    print(f"Digits of p recovered: {res}")
    given_p = int(str(res).ljust(78, '0'))
    upper_p = int(str(res).ljust(78, '9'))
    diff_bits = len(bin(given_p ^ upper_p)[2:])
    common_bits = bin(given_p)[2:2+256-diff_bits]

    # get 2 more bits
    for i in range(2):
        data = {
                'query': f'SELECT CASE p>="{int((common_bits+"1").ljust(256, "0"), 2)}" WHEN 1 THEN "UwU" ELSE ":(" END FROM npqc_table;',
            }
        response = s.post(url, data=data)
        resp = response.text.split('\n')[0]
        if "UwU" in resp:
            common_bits+="1"
        else:
            common_bits+="0"
    print(f"p: {common_bits.ljust(256, '*')}")
    response = s.post(url, data={
        "generate_ciphertext":"finger_xxed"
    })

    _, _, c, _, n, *_ = response.text.split('\n')
    c, n = [int(x.strip()) for x in [c,n]]

    print(f"n: {n}\n\nc: {c}")
    print("Good luck grhkm")
    break
```

The final part is hardcore crypto with Coppersmith, which I'm really unfamiliar. It's a brief summary (hope I'm correct):
- From Coppersmith, with N being k-bit, if the upper or lower k/4 bits of p is known, RSA can be efficiently bracked.
- The solution involves finding a small root of *some expression* under *some polynomial ring*

This is where grhkm's experience really shined (shone?), he wrote the whole sage script and we just changed numbers.
It took around half an hour and churned out a `p`, the flag comes subsequently.

```py
import itertools

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []


from tqdm import tqdm, trange

set_verbose(0)

DEBUG = 0

prefix_p = "11110101100001010011110111100011101101100110000010011010100100011010001011101101001110101010100001101000110110010101100001001"
N = 7324087135823320300123705242890254429169625192676966370032001493951473563239537604617766714046443799154373566371428927941894885863906862624074822340169673
C = 6275775089001584971907777902842854979613137112017232591292951828145252379342183519738265842780769019316358862883095105904985918369600922940920249077464143

START, END = 0, 10^6

R = Integers(N)
P = PolynomialRing(R, 1, 'x')
Pgen = P.gen()

def doit(n):
	prefix = prefix_p + bin(n)[2:].rjust(11, '0')
	given_p = int(str(prefix).ljust(256, '0'), 2)
	upper_p = int(str(prefix).ljust(256, '1'), 2)
	delta_p = upper_p - given_p
	assert delta_p <= 2^120
	f = given_p + Pgen
	root = small_roots(f, bounds=[delta_p], m=9, d=10)
	if len(root) == 0:
		return
	recovered_p = ZZ(f.change_ring(ZZ).subs(x = ZZ(root[0][0])))
	print(recovered_p, recovered_p.nbits(), N % recovered_p == 0)

for n in tqdm(range(2048)): 
	doit(n)
```

### Official Solution

**Simplified version**

It turned out 1024>1000 isn't the best solution. It's easy to think *"oh we must avoid not returning something at all cost as we get punished by having 1 fewer request"*, but since it's just **double cost**, we just arrange such that those requires return twice the info. Recalling `10=4+4+2` we can thus write:

|    | digit of p | digit of p | digit of p |
| ------------- | ------------- | ------------- | ------------- |
| query  | 0~3 | 4~7 | 8~9 |
| 0\~3 UwU, 4\~7 :(  | UwU [-1]  | :( [-1] | [-2] |
| UwU if digit & 2 else :( | [-1] | [-1] | N/A |
| LSB | 🚩 | 🚩 | :🚩 |

Thus we can have 3reqs/digit instead of 10reqs/3digit. This is already more than enough for the flag.

**Actual solution**

Kin mind holders will notice that the above solution isn't optimal - *For 0~3 or 4~7 we can reuse the same principle to look for |01|2|3| or |45|6|7|*. This further increases the rate to 2.8reqs/digit. The provided official solution uses ternary search with equal intervals, however upon research:
- 2/5|2/5|1/5 works better due to the aforementioned reason.
- getting 2 digits at a time will usually result in more digits being recovered, but there's higher risk of wasting some final requests.

With this way it's not surprising to get 150 bits and the typial small_roots solution can be used.

```py
R.<x> = PolynomialRing(Zmod(n))
bits = int(log(guess_for_p) / log(2))
f = x * 10^counter + guess_for_p
factors = f.monic().small_roots(beta = 0.48, epsilon = 0.02, X = 2^(256 - bits))
```
