
> This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

```html
|   |
|---|
|var isAdmin = false;|
||if (isAdmin) {|
||var topLinksTag = document.getElementsByClassName("top-links")[0];|
||var adminPanelTag = document.createElement('a');|
||adminPanelTag.setAttribute('href', '/admin-u0dz5n');|
||adminPanelTag.innerText = 'Admin panel';|
||topLinksTag.append(adminPanelTag);|
||var pTag = document.createElement('p');|
||pTag.innerText = '\|';|
||topLinksTag.appendChild(pTag);|
```

