# Why not?

https://ringzer0ctf.com/challenges/34

Very funny one!

This is our code of interest:

```
/ Look's like weak JavaScript auth script :)
	$(".c_submit").click(function(event) {
		event.preventDefault();
		var k = new Array(176,214,205,246,264,255,227,237,242,244,265,270,283);
		var u = $("#cuser").val();
		var p = $("#cpass").val();
		var t = true;
			
		if(u == "administrator") {
			for(i = 0; i < u.length; i++) {
				if((u.charCodeAt(i) + p.charCodeAt(i) + i * 10) != k[i]) {
					$("#cresponse").html("<div class='alert alert-danger'>Wrong password sorry.</div>");
```

Our first assumption is that password length = username lenght (13 characters, as in `administrator`).

This `if` statement compares every character with the ones in "k" array:

```
u.charCodeAt(i) + p.charCodeAt(i) + i * 10) != k[i]
```

So, the *formula* for every character is:

```
p.charCodeAt(i) = k[i] - u.charCodeAt(i) - i * 10
```

Let's build an list (`admin_list`) with chars of `administrator` string:

```
>>> admin_list = []
>>> user = 'administrator'
>>> for i in range(len(user)):
...     admin_list.append(ord(user[i]))
...
>>> print(admin_list)
[97, 100, 109, 105, 110, 105, 115, 116, 114, 97, 116, 111, 114]
```

Now, let's define a list with the items in "k" array in original javascript code:

```
>>> k = [ 176,214,205,246,264,255,227,237,242,244,265,270,283 ]
```

Now we can obtain chars from previous *formula*:

```
>>> for i in range(len(user)):
...     p = k[i] - admin_list[i] - i * 10
...     print(p)
...
79
104
76
111
114
100
52
51
48
57
49
49
49
```

Let's convert every char:

```
>>> for i in range(len(user)):
...     p = k[i] - admin_list[i] - i * 10
...     print(chr(pass_list[i]))
...
O
h
L
o
r
d
4
3
0
9
1
1
1
```

Better:

```
>>> for i in range(len(user)):
...     p = k[i] - admin_list[i] - i * 10
...     print(chr(pass_list[i]), end='')
...
OhLord4309111
```

So credentials are:

user: `administrator`
pass: `OhLord4309111`









