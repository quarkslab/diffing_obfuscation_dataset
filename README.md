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


