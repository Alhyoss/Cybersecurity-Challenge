from base64 import *
import zlib
import codecs
import itertools
import urllib
import json

trad = "Top Secret !!!  A novel substance was sucessfully extracted from the leaves of the tea bush and also from kola nuts.  After complex and dangerous experimetnts a white solid was obtained with a melting point of 500K.  Chemical analysis revealed the followibg composition: 1,3,7-Trimethylpurine-2,6-dione. This new subtance will change the way in which people will be able to work,  hackers will write even more l33t c0d3 and provide hipsters with an essential ingredient for their gatherings. --What is the CSCBE flag 1?"

codes = "1f620e09863c3d9321492c06096b3e492012489b3b5dc03d3d6d305d082d5d9e2148301109a21158d93309a22a1f5817580f13484d0a58e535097f0e091d1304e70609ba0e16031809ab1b589b0e4817395d782f040e124961231f8a3e49100958a11e58cc0904e6004933003d7a2a4881251fc30b191f325d7f3609e00f097400487e0b04350e1f96215dfe1d49342904b42909753358f93858c43158d401048520048e352e140e09dc0e5dd03158a0331f5437584208485c1458a02d3d742a5d91363d8d1b3d660704a62f2e2f283d66025885351f603e4918092e083709d13209630d58c80158f730095c2749523e1f822a04db024915020938052e182f49310409630d09e4265dfa03489408044217099a174859163d530d58690758471e041027488b143dae151f841a1f1e3804350d5dd0015d623858872c5d9e211f15235d5233042e3d588b125de7294813394858373d1125042c145d973b3d891848252f1f88023dac0209e10a04f60958011f58f5312e18323d38391f791c5854035d292858241409490a580f0104f13658e12904e73548733d5d56295d201404fd1f09882304321d2e1f3449762b09ae1848041e04d72604b3231f4f1e09452049741b58d00709be2c04b80f5db22e58b30e04c610040e125dc73b5dd91c58e1001f2e0858210b0455011f831904471d09a3243d2a0a04592b0948114965383d2b3358b32e48812558210b09ed1f097c04492c06496c20482c021fd7101fa119494f1a49220b48043158a432487333495c053d751c1fac205ded1004ca1509a32d584e225dc81b04653a5802353d8d1b5d03381f1f2c4820135d1d225d81123da3285d56195d3c04048b2e5dc3015d5d384861385876071fc43004241704d3381f5a2b3d080904c31f099d2d04663758183e58f70a580b0658d92e58e6082e211c04e934193e1016040304012119061048552c09903158b31904142a48213d09701d3d0b075824143d3d3c1f3c2b5d0d2e3d581309cc131f5e1858692e1f29220454105daa1604cd2f493e1e040c3b04702a3d391e58ee1348281c04d30e58b82d48581f58592e193e0c046408160620584c305d8c1404f42f04c90509e23004d30e493a012e391704ce071f1e1f58c1375d6c1e09eb1e58293209ac3958f234096b0004d03358b52f094e222e182f1fac20493d3d5d5f3a5dfe1d047b1a1f0312585a0258992c3daa1849673e09d6003da30e58482e588e113d192b4952343da40509612958083719311e09a41a2e201c5831132e202909b8104873224846175d8c285d721f5dac265de00909340a58223c58653e5891093d5733484422497811497b0904ac225db93809173b3da8295d9e051fa8132e2f32484f28048b2b042f120970355d4d0f3d9a040908161f1e30048102092e085dc41704622404e42e1f2f015dee1c485506094d3d09b6074919151f742d0992342e1214580c06584a2004901209e52e2e202748570858b40c04ff061f2d0409be2c4857083da4152e082b19292009943b19092f3d1f151f6227098e1a496b00192f0809df145d991f3d19390966190952041921291f061b1fcb2f48251004940309233a1f213858212948360a1fc23e160b083d9b2f584f19046c0b5d56193d391e1f312c482510097e173d8e02190615097309485e2d584e221fae3b49602c04453c09ca1258c62a48170404482758f6213d203858f622496e120943125d14243d7639094e035d4b2458c62c58690716012b1feb1b1fac305839351f5e185dc3015859171fb13958082909ea02094f211f933409943b58cc091f753c04ec1a4964091f0b1549170a048c214869303d3f23093106097e171f10335d53302e1e254825101f0a203da41c496809496f1c5d830f1fd42f58022f58680d5d0e24047b3209272258ab23097e1a04532b5d9b144939095d162609bf1e1fbf1204f30a04db0204ee2f4808354973345d9b3e485f2a58210409c514042030042a3e48201f48902c58b0285d570f5d9f045d58091f4f093d660758982e1fb82209e72f585c3e1fe51d09371c5d593c2e200c0403341921165d5119494e31581e35585e3e04fe065d6d3504f404480e3b048c0a5d441309fb021fb00c588714042e3b58842d1f811019242f5d9e211fef3a486b2b09cd39044a255dee025d280304980c"

dict = {}

"Dear 0r&cl# (what is Flag3)"

for i, c in enumerate(trad):
	dict[c] = codes[i*6: i*6 + 6]

new = "331309"
dict['('] = "09fb0a"
dict['#'] = "09fb0c"
dict['O'] = "09fb3d"
dict[')'] = "09ce35"
dict['&'] = "486c16"
dict['F'] = "486c2b"
dict['D'] = "1ff023"

string = dict['D']+dict['e']+dict['a']+dict['r']+dict[' ']+dict['0']+dict['r']+dict['&']+dict['c']+dict['l']+dict['#']+dict[' ']+dict['(']+dict['w']+dict['h']+dict['a']+dict['t']+dict[' ']+dict['i']+dict['s']+dict[' ']+dict['F']+dict['l']+dict['a']+dict['g']+dict['3']+dict[')']
print(string)


