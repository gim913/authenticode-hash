authenticode-hash
=================

Old code for calculating (and checking) Authenticode hash in D

If you'd like to compile this, you're gonna need *some* version of http://dsource.org/projects/tango
but I don't remember which one :P (I guess 0.99.8 or earlier)

compile is d breeze with `rebuild` from dsss http://www.dsource.org/projects/dsss/wiki/Rebuild

---

I've been asked few question, so I thout I'll answer them upfront.

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

Now this is, where `mixin` comes into play, or more actually `string mixins`, so this innocen line:
```d
    mixin (AddressRound!("rva", "VirtualAddress",       "SectionAlignment"));
```

actually gets evaluated at *compile-time*, to following method inside `ImageSectionHeader` class:
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


