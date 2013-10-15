authenticode-hash
=================

Old code for calculating (and checking) Authenticode hash in D

If you'd like to compile this, you're gonna need *some* version of http://dsource.org/projects/tango
but I don't remember which one :P (I guess 0.99.8 or earlier)

compile is d breeze with `rebuild` from dsss http://www.dsource.org/projects/dsss/wiki/Rebuild

---

I've been asked few question, so I thought I'll answer them upfront.


AddressRound
------------

Both `AddressRound` and `SizeRound` are templates very special templates.

Normally in D you'd write template function like this:

```d
template Foo(T)
{
    T bar(T t) {
        return t * T.sizeof;
    }
}
```

and then instantiate it like:

```d
void main() {
    alias Foo!(int) IntBar;
    writeln( IntBar.bar(10) );

    // or alternatively
    writeln( Foo!(double).bar(10) );
}

// produces 40 and 80
```

but D has some syntactic sugar:
> If a template has exactly one member in it, and the name of that member
> is the same as the template name, that member is assumed to be referred
> to in a template instantiation:

so you can rewrite the above as:

```d
template bar(T) {
    // renamed to Foo
    T bar(T t) {
        return t * T.sizeof;
    }
}

void main() {
    alias bar!(int) intBar;
    writeln( intBar(10) );

    // or alternatively
    writeln( bar!(double)(10) ); 
    // instead of boring: bar!(double).bar(10)
}

// produces 40 and 80
```

So instantiating `AddressRound` template will actually produce a string...
...and as you might know, templates are calculated at compile time.

Now this is, where `mixin` comes into play, or more actually `string mixins`, so this innocent line:
```d
    mixin (AddressRound!("rva", "VirtualAddress",       "SectionAlignment"));
```

actually gets evaluated at **compile-time**, to following method inside `ImageSectionHeader` class:
```d
    uint rva() {
        uint ret=VirtualAddress;
        if (this.outer.imgopt.io32.SectionAlignment) {
            ret /= this.outer.imgopt.io32.SectionAlignment;
            ret *= this.outer.imgopt.io32.SectionAlignment;
        }
        return ret;
    }
```


RetriveFields
-------------

The other thing is `RetriveFields` template.

But lets start with (old) `tango.io.protocol.Reader`, thanks to it, you could read from an `InputStream` (or few other interfaces) in following, little bit funny way:

```d
// InputStream fp
//
auto read = new Reader(fp);

int count;
double pi;
char[] verse;

read (pi) (verse) (count);

// above one is actually:
// read.get(pi).get(verse).get(count);
```

`RetriveFields` is **recursive template** that at compile-time will produce representation of some simple struct or class, in a very specific form.

As stated in comment in code the following code
```d
struct A { int inA_1; }
struct B { char inB_1; A inB_2; }
struct C { B inC_1; A inC_2; float inC_3; }

mixin ("read " ~ RetriveFields!(C, "ccc", 0) ~ ";");
```

will be evaluated (at compile-time) to following statement:
```d
mixin ("read (ccc.inC_1.inB_1) (ccc.inC_1.inB_2.inA_1) (ccc.inC_2.inA_1) (ccc.inC_3);");
```

which `string mixin` puts into the code as:
```d
    read (ccc.inC_1.inB_1) (ccc.inC_1.inB_2.inA_1) (ccc.inC_2.inA_1) (ccc.inC_3);
```

OFC, this is *crazy*, and normally you'd just **read the struct as binary blob** with proper packing/alignment.

I just thought it'll be **fun** to do it this way, writing it was fun indeed.


Static If + version
-------------------

There are **static ifs** inside `RetriveFields`, those are part of so called *conditional compilation*, more on that here:
http://dlang.org/version.html#StaticIfCondition

Inside calcSum.d there are also `version()` blocks (also part of *conditional compilation*)
http://dlang.org/version.html#version

