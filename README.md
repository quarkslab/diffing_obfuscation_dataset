# Obfuscation-Dataset

Welcome to the official repository of the Obfuscation-Dataset.

> [!WARNING]
> This repository is related to an ongoing work. It is currently subject to changes. 


[//]: <> It was produced and published with the paper [TODO]. 

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

## Usage

TODO: Installation

TODO: Usage of helper cli tool

## Detailed description

The dataset is organized as follows. 

```bash
 dataset
 ├── project-name
 │   ├── obfuscated
 │   │   ├── obfuscator
 │   │   │   ├── obfuscation-type
 │   │   │   │   └── (optional) obfuscation-type refinement
 │   │   │   │       ├── obfuscation-pass
 │   │   │   │       │   ├── obfuscation-level
```

Each final folder contains a list of files. For example, the folder:
```bash 
dataset/zlib/obfuscated/tigress/controlflow/intra/flatten/50/
```
contains the list of the zlib project, obfuscated with the Tigress obfuscator, using an intra-procedural obfuscation, which is the Flattening (Controlflow), for which 50% of the zlib functions are obfuscated. 

Each final folder contains a list of original .c files and the corresponding .exe binaries. Binaries are stripped but symbols (function names) can be found in the corresponding .json files, that maps function addresses to their name. 
Binaries are compiled for architecture x86-64, either in -O0 or -O2. 

Each folder also contains exported binaries files: .BinExport, .Quokka and eventual .sqlite.


We consider five projects : zlib, lz4, minilua, sqlite and freetype. They were chosen because they are currently the only projects than can be found on the Internet under an amalgamate form. 
An amalgamate C file is a project in C that stands in a single and unique C file. Amalgamating C project is difficult. Such constraint can be explained by the fact Tigress obfuscation works well only on amalgamate C file.

> It might be possible to use the cilly-merge Tigress functionality that allows to merge multiple C files into one. However, we cannot make it work on realistic binaries. That explains why we directly work on amalgamate C files, which restricts the number of available projects.

We use two obfuscators : Tigress and OLLVM. Tigress is a source-to-source obfuscator whereas OLLVM compiles a binary by integrating directly obfuscation into it. OLLVM was ported to LLVM-14.

> Notice that Tigress, due to internal error, may not succeed to produce an obfuscated source code or, if it does, the obfuscated .c file may not compiled, despite all our efforts. This explains why for example the sqlite project has no binaries obfuscated with the Virtualization passes.

> The obfuscation of OLLVM remains as they are, we do not apply further change to make the passes compatible with LLVM-14. Instead, we make sure that OLLVM binaries can be compiled using LLVM-14.


We study the following Tigress obfuscation passes, given their type:

- Data/EncodeArithmetic and Data/EncodeLiterals. 
- Controlflow/Intra/Flatten, Controlflow/Intra/Virtualize, Controlflow/Intra/Opaque
- Controlflow/Inter/Copy, Controlflow/Inter/Merge, Controlflow/Inter/Split

We use these passes using their default parameters. 
We also created a new obfuscation class, called "Combined". It contains two obfuscation schemas : Intra/Flatten + Data/EncodeArithmetic + Intra/Opaque and the same one + Controlflow/Inter/Split. These two obfuscation schemas represent a real-case scenario where a function is not obfuscated with a single pass but with multiple that are combined together.

For OLLVM, we consider:

- Data/EncodeArithmetic ~ Data/Sub
- Controlflow/Intra/Flatten and Controlflow/Intra/Opaque ~ Controlflow/Intra/BogusControlflow
- Combined = Controlflow/Intra/Flatten + Data/EncodeArithmetic + Controlflow/Intra/Opaque

Such obfuscation combination is applied in that order. 

> The combined obfuscation schema means that each function is obfuscated with this precise schema. If a function is obfuscated, it means it was obfuscated with first a Flattening then an EncodeArithmetic then an Opaque. It means there is no function in the binary that was only obfuscated with a Flattening and a Opaque or a Flattening alone. 

Our binaries are obfuscated depending on a obfuscation level. Such obfuscation level determine the percentage of functions that are obfuscated inside a binary, considering the selected obfuscation pass.

Similarly, our binaries are obfuscated given a seed. It influences how the obfuscation was applied (see [TODO]).

> Example. The binary "dataset/zlib/obfuscated/tigress/controlflow/intra/flatten/50/zlib_obfuscated_tigress_controlflow_intra_flatten_50_3.c.exe" indicates that the project zlib was obfuscated using Tigress with a intra-procedural obfuscation that flattens the controlflow. 50% of the functions are obfuscated and the seed is set to 3.

> Notice that the obfuscation level indicates the percentage of functions obfuscated inside a binary. It does not indicate the obfuscation ratio applied within a function. For example, 50% indicates that 50% of the binary function were obfuscated given an obfuscation schema, but it does not mean that 50% of a function content were obfuscated.

A sum-up of the dataset is available in the Table below: [TODO].



# How to contribute

A dataset is not a immutable amount of data. It should be enriched over time. 

Any help to enhance this dataset is warmely welcome. In particular, we would appeciate:

- Any help related to the creation of amalgamate C files. One Tigress current constraint is to use amalgamate C files. Such file are difficult to find. If you know an amalgamate project that is not in the dataset, please let us know. 
- Any help related to the obfuscator used. We currently support OLLVM (rebased on LLVM-14) and Tigress 3.1.11. If you know another (free) obfuscators, please let us know. Notice that forks of OLLVM do not represent a real added values. 
- Any help related to the binaries compilation. Our dataset only contains x86-64 binaries, either compiled in -O0 or -O2. If you want to add other optimization levels (-O1, -O3, -Os), please feel free to do it. If you want to add other architecture, it might be possible (even thought a bit more difficult than just recompiling binaries with other optimization level). Please contact use for more info. 

