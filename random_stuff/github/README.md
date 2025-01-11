### Create SSH keypair:

```
ssh-keygen -t rsa -C github
```

(then we need to upload **public** key to our repository)

start SSH agent and add our private key:

```
eval $(ssh-agent)
ssh-add id_rsa_github
```

### switch to ssh authentication

```
git remote set-url origin git@github.com:sughenji/nomedelrepository.git
```

### check if local repo is up-to-date with remote

```bash
$ git remote show origin
* remote origin
  Fetch URL: https://github.com/sughenji/Joyce.git
  Push  URL: https://github.com/sughenji/Joyce.git
  HEAD branch: main
  Remote branch:
    main tracked
  Local branch configured for 'git pull':
    main merges with remote main
  Local ref configured for 'git push':
    main pushes to main (up to date) <===========
```

