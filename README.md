### WIP: Not ready, not safe. 


Or as described in the [documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/)


> This is a “Hazardous Materials” module. You should ONLY use it if you’re 100% absolutely sure 
> that you know what you’re doing because this module is full of land mines, dragons, 
> and dinosaurs with laser guns.

Make sure you generate a strong seed at least 256-bit long

i.e: `SEED=$(head -c 32 /dev/urandom | xxd -p -c 32)`

then run the script to generate your keys like:

`python3 ssh_key_gen.py --seed $SEED --comment foo@bar.home`

store your `$SEED` in a safe place and integrate this tool with your, for instance, devops processes


Inspiration: https://github.com/mithrandi/ssh-key-generator/tree/master