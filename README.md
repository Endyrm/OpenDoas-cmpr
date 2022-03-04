# OpenDoas-cmpr: a portable version of OpenBSD's `doas` command with the ability to set password prompt through the environment variables

All the information and documentation about OpenDoas itself can be found in [the original repo](https://github.com/Duncaen/OpenDoas "the original repo") or in the [Arch Wiki](https://wiki.archlinux.org/title/Doas "Arch Wiki")

This fork adds the ability to set password prompt and error message using the `DOAS_PROMPT` and `DOAS_AUTH_FAIL_MSG` environment variables

Example of usage:

![](example.png)

TODO:
- Add ANSI escape codes support
