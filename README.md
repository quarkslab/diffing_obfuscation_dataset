# Obfuscation-Dataset

Welcome to the official repository of the Obfuscation-Dataset.

> [!WARNING]
> This repository is related to ongoing works. It is currently subject to changes. 

It was produced and published with ongoing submitted papers. 

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

## Description 

The dataset is organized as follows. 

```bash
 dataset
 ├── project-name
 │   ├── obfuscated
 │   │   ├── obfuscator
 │   │   │   ├── obfuscation-pass
 │   │   │   │   ├── obfuscation-level
 |   |   |   |   |
 |   ├── sources
```

Each project is associated to the original sources (unobfuscated) along with obfuscated binary variants. Each obfuscated final folder contains a list of files. For example, the folder:
```bash 
dataset/zlib/obfuscated/tigress/CFF/50/
```
contains the list of the zlib project, obfuscated with the Tigress obfuscator, using the Control-Flow Graph Flattening pass (CFF) for which 50% of the zlib functions are obfuscated. Such a folder contains the original .c files and the corresponding .exe binaries. Binaries are stripped but symbols (function names) can be found in the corresponding .json files, that maps function addresses to their name. Each folder also contains exported binaries files: .BinExport and .Quokka.

Currently, the dataset provides:

- five projects: zlib, lz4, minilua, sqlite, freetype
- two obfuscators: OLLVM and Tigress
- a large set of obfuscation: CFF, opaque, encodearith, mix1 (common to both OLLVM and Tigress), along with virtualization, copy, merge, split, mix2 (specific to Tigress)
- obfuscation level, from 0% (folder sources), up to 100%, with a 10% step
- x64 architecture
- -O0 or -O2 binaries

## Usage

This dataset is provided along with a python package that aims to ease data download in particular. It can be installed as follows (preferably inside a virtual env):
```
git clone git@github.com:quarkslab/diffing_obfuscation_dataset.git
cd diffing_obfuscation_dataset
pip install .
```

Once the package is installed, the following commands are available : 

```
obfu-dataset-cli --help
Usage: obfu-dataset-cli [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  compile              
  create
  download-all
  download-obfuscated
  download-plain
  export
  ls
  strip
```
### Use the dataset

The ```download-all``` command downloads the plain (sources) folders and the obfuscated folders for all the projects. 

> This step requires to download approximately 92GB of data (be patient)

The ```downdload-obfuscated``` and ```download-plain``` commands respectively download obfuscated and plain (sources) folders. [TODO examples]

The ```ls``` command helps the user to manually check what has been downloaded. [TODO example]

These three commands are sufficient for any users that would like to use this dataset. 

### Recreate the dataset

The ```create, compile, strip, export``` commands are available for people that would like to recreate the dataset.

> Recreating the whole dataset will require a lot of time. Notice that we do not guarantee that the produced binaries will be exactly the sames as the ones provided (due to compilation specificities, see [TODO])


## Detailed description

We consider five projects : zlib, lz4, minilua, sqlite and freetype. They were chosen because they are currently the only projects than can be found on the Internet under an amalgamate form. 

An amalgamate C file is a project in C that stands in a single and unique C file. Amalgamating C project is difficult. Such constraint can be explained by the fact Tigress obfuscation works well only on amalgamate C file.

> It might be possible to use the cilly-merge Tigress functionality that allows to merge multiple C files into one. However, we cannot make it work on realistic binaries. That explains why we directly work on amalgamate C files, which restricts the number of available projects.

We use two obfuscators : Tigress and OLLVM. Tigress is a source-to-source obfuscator whereas OLLVM compiles a binary by integrating directly obfuscation into it. OLLVM was ported to LLVM-14.

> Notice that Tigress, due to internal error, may not succeed to produce an obfuscated source code or, if it does, the obfuscated .c file may not compiled, despite all our efforts. This explains why for example the sqlite project has no binaries obfuscated with the Virtualization passes.

> The obfuscation of OLLVM remains as they are, we do not apply further change to make the passes compatible with LLVM-14. Instead, we make sure that OLLVM binaries can be compiled using LLVM-14.

We study the following Tigress obfuscation passes, given their type: [TODO, give links]

- Data obfuscation: encodearith and encodeliteral
- Intra-procedural obfuscation: CFF, virtualize, opaque
- Inter-procedural obfuscation: copy, merge, split

We use these passes using their default parameters. 
We also created a new obfuscation classes called: mix1 and mix2. Mix1 combines CFF, encodearith and opaque whereas mix2 combines mix1 and split. These two obfuscation schemas represent a real-case scenario where a function is not obfuscated with a single pass but with multiple that are combined together.

For OLLVM, we consider:[TODO add links]

- Data obfuscation: encodearith ~ Data/Sub
- Intra-procedural obfuscation: CFF and opaque ~ Controlflow/Intra/BogusControlflow
- mix1 = CFF + encodearith + opaque

> The combined obfuscation schema means that each function is obfuscated with this precise schema. If a function is obfuscated, it means it was obfuscated with first a Flattening then an EncodeArithmetic then an Opaque. It means there is no function in the binary that was only obfuscated with a Flattening and a Opaque or a Flattening alone. 

Our binaries are obfuscated depending on a obfuscation level. Such obfuscation level determine the percentage of functions that are obfuscated inside a binary, considering the selected obfuscation pass.

Similarly, our binaries are obfuscated given a seed. It influences how the obfuscation was applied (see [TODO]).

> Example. The binary "dataset/zlib/obfuscated/tigress/CFF/50/zlib_obfuscated_tigress_controlflow_intra_flatten_50_3.c.exe" indicates that the project zlib was obfuscated using Tigress with a intra-procedural obfuscation that flattens the controlflow. 50% of the functions are obfuscated and the seed is set to 3.

> Notice that the obfuscation level indicates the percentage of functions obfuscated inside a binary. It does not indicate the obfuscation ratio applied within a function. For example, 50% indicates that 50% of the binary function were obfuscated given an obfuscation schema, but it does not mean that 50% of a function content were obfuscated.

A sum-up of the dataset is available in the Table below: [TODO].



# How to contribute

A dataset is not an immutable amount of data. It should be enriched over time. 

Any help to enhance this dataset is warmely welcome. In particular, we would appeciate:

- Any help related to the creation of amalgamate C files. One Tigress current constraint is to use amalgamate C files. Such file are difficult to find. If you know an amalgamate project that is not in the dataset, please let us know. 
- Any help related to the obfuscator used. We currently support OLLVM (rebased on LLVM-14) and Tigress 3.1.11. If you know another (free) obfuscators, please let us know. Notice that forks of OLLVM do not represent a real added values. 
- Any help related to the binaries compilation. Our dataset only contains x86-64 binaries, either compiled in -O0 or -O2. If you want to add other optimization levels (-O1, -O3, -Os), please feel free to do it. If you want to add other architecture, it might be possible (even thought a bit more difficult than just recompiling binaries with other optimization level). Please contact use for more info. 

