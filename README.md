WIP

Make sure you generate a strong seed at least 256-bit long

i.e: `SEED=$(head -c 32 /dev/urandom | xxd -p -c 32)`

then run the script to generate your keys like:

`python3 ssh_key_gen.py --seed $SEED --comment foo@bar.home`

store your `$SEED` in a safe place and integrate this tool with your, for instance devops processes
