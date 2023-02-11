# Client side validation is bad!

https://ringzer0ctf.com/challenges/27

Let's look at source code:

```
// Look's like weak JavaScript auth script :)
	$(".c_submit").click(function(event) {
		event.preventDefault()
		var u = $("#cuser").val();
		var p = $("#cpass").val();
		if(u == "admin" && p == String.fromCharCode(74,97,118,97,83,99,114,105,112,116,73,115,83,101,99,117,114,101))
```

We can obtain original string from browser's console:

```
String.fromCharCode(74,97,118,97,83,99,114,105,112,116,73,115,83,101,99,117,114,101)
"JavaScriptIsSecure"
```

So we can login with user: `admin` and password `JavaScriptIsSecure` and obtain flag!
