# ips.py

A Python library for handling IPS patches.

I wanted to create this as there was no suitable library for how I wanted to manipulate IPS patches, which at the time was just changing the offsets in the records. Since then I have wanted to extend it for my own needs, and for the potential needs of others.

The logic for creating patches from two file objects is taken from [flips](https://github.com/Alcaro/Flips/), which creates very good, small patches.

### How to use

To import the library, do

```py
import ips
```

To get a `Patch` object from an IPS file, do

```py
with open("path/to/patch.ips", "rb") as f:
    p = ips.Patch.load(f)
```

If you already have the bytes of the IPS file, you can do

```py
with open("path/to/patch.ips", "rb") as f:
    cont = f.read()

...

p = ips.Patch.load(cont)
```

To apply a `Patch` object, do

```py
with open("path/to/original/file.bin", "rb") as old, open("path/to/new/file.bin", "wb") as new:
    p.apply(old, new)
```

If you don't want to necessarily write it to a new file, you can do

```py
import io

new = io.BytesIO()
with open("path/to/original/file.bin", "rb") as old:
    p.apply(old, new)
```

To create a `Patch` object from two file objects, do

```py
with open("path/to/original/file.bin", "rb") as old, open("path/to/new/file.bin", "rb") as new:
    p = ips.Patch.create(old, new)
```

To pack a `Patch` object into a `bytes` object, do

```py
bytes(p)
```

To add a record to a `Patch` object, use the `add_record` method.

To get a list of records in a `Patch` object, use the `records` attribute.

To get whether a `Patch` object is using the IPS32 format, which allows for offsets up to 4 GiB, check the `ips32` attribute.