# open-nFAPI
 
Open-nFAPI is implementation of the Small Cell Forum's network functional API or nFAPI for short. 
nFAPI defines a network protocol that is used to connect a Physical Network Function (PNF) 
running LTE Layer 1 to a Virtual Network Function (VNF) running LTE layer 2 and above. The specification
can be found at http://scf.io/documents/082.
 
The aim of open-nFAPI is to provide an open interface between LTE layer 1 and layer 2 to allow for
interoperability between the PNF and VNF & also to facilitate the sharing of PNF's between
different VNF's

Open-nFAPI implements the P4, P5 and P7 interfaces as defined by the nFAPI specification. 
* The P5 interface allows the VNF to query and configure the 'resources' of the PNF; i.e slice it into
 1 or more PHY instances.
* The P7 interface is used to send the subframe information between the PNF and VNF for a PHY instance
* The P4 interface allows the VNF to request the PNF PHY instance to perform measurements of the surrounding network

The remaining interfaces are currently outside of the scope of this project.

The Small Cell Forum cordially requests that any derivative work that looks to 
extend the nFAPI libraries use the specified vendor extension techniques, 
so ensuring the widest interoperability of the baseline nFAPI specification 
in those derivative works. 

## Licensing

The open-nFAPI libraries are release by CISCO under an Apache 2 license. 

## Downloading

The open-nFAPI project can be pulled from git hub

```
git clone https://github.com/cisco/open-nFAPI.git nfapi
```

The following dependencies are required
* BOOST
* SCTP


## Building

To build the open-nFAPI project

```
autoreconf -i
./configure
make
```

To run the unit and integration tests

```
make check
```

