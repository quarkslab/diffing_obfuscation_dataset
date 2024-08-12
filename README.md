# Obfuscated dataset: [FIND A NAME]

Welcome to the official repository of the [NAME] dataset. 
It was produced and published with the paper [TODO]. 

## Introduction

Current obfuscation research lacks of a large dataset that contains various realistic binaries (not only code snippets such as sorting algorithms), multiple obfuscators (not only OLLVM) and diverse obfuscation types and passes (not only Control-Flow Graph Flattening). 

This dataset aims to be a first step to fill the gap. It respects several requirements : 

- C compiled code. This dataset only contains binaries whose source code is in C.
- Realistic binaries. This dataset contains several projects : zlib, lz4, minilua, sqlite and freetype. 
- Multiple obfuscators. We consider two free obfuscators that are OLLVM and Tigress. 
- Multiple obfuscation types and passes. Various obfuscations are proposed: intra-procedural or inter-procedural obfuscation as well as data obfuscated. 
- Large amount of data. This dataset contains more than 6,000 binaries, that represent more than 8M of functions. 

This dataset can be used for many research subject centered around obfuscation, such as : 

- Deobfuscation
- Obfuscation detection
- Diffing of obfuscated binaries...

# Detailed description

The dataset is organized as follows. 

> dataset
> ├── project-name
> │   ├── obfuscated
> │   │   ├── obfuscator
> │   │   │   ├── obfuscation-type
> │   │   │   │   └── (optional) obfuscation-type refinement
> │   │   │   │       ├── obfuscation-pass
> │   │   │   │       │   ├── obfuscation-level

Each final folder contains a list of files. For example, the folder:
> dataset/zlib/obfuscated/tigress/controlflow/intra/flatten/50/
contains the list of the zlib project, obfuscated with the Tigress obfuscator, using an intra-procedural obfuscation, which is the Flattening (Controlflow), for which 50% of the zlib functions are obfuscated. 

Each final folder contains a list of original .c files and the corresponding .exe binaries. Binaries are stripped but symbols (function names) can be found in the corresponding .json files, that maps function addresses to their name. 
Binaries are compiled for architecture x86-64, either in -O0 or -O2. 

Each folder also contains exported binaries files: .BinExport, .Quokka and eventual .sqlite.


# How to contribute

A dataset is not a immutable amount of data. It should be enriched over time. 

Any help to enhance this dataset is warmely welcome. In particular, we would appeciate:

- Any help related to the creation of amalgamate C files. One Tigress current constraint is to use amalgamate C files. Such file are difficult to find. If you know an amalgamate project that is not in the dataset, please let us know. 
- Any help related to the obfuscator used. We currently support OLLVM (rebased on LLVM-14) and Tigress 3.1.11. If you know another (free) obfuscators, please let us know. Notice that forks of OLLVM do not represent a real added values. 
- Any help related to the binaries compilation. Our dataset only contains x86-64 binaries, either compiled in -O0 or -O2. If you want to add other optimization levels (-O1, -O3, -Os), please feel free to do it. If you want to add other architecture, it might be possible (even thought a bit more difficult than just recompiling binaries with other optimization level). Please contact use for more info. 

