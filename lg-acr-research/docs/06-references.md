# Public references and relation to this work

- [IMC 2024: Watching TV with the Second-Party](https://arxiv.org/html/2409.06203v1). The conclusion identifies advanced MITM payload understanding as future work. That motivates this case study; it does not prove worldwide novelty.
- [Scriptbase webOS 24 report](https://scriptbase.org/lg-tv/webos-24.html). Static investigation on a different model/build. Distinguish static capability from observed messages.
- [GamersNexus original LG investigation](https://www.youtube.com/watch?v=6IFVTcM28KA). HDMI traffic discussion around27:54, encrypted-payload uncertainty around30:58, local ACR audio saved before hashing around1:55:25. Full supplied transcript reviewed; visual demonstrations not independently reviewed in full. The later response video was not reviewed in full.
- [LG privacy statement](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs). Manufacturer position. ACR and voice recognition require separate evidence.
- [Baluja and Covell audio fingerprinting research](https://research.google/pubs/audio-fingerprinting-combining-computer-vision-data-stream-processing/). Established Haar/sign/MinHash background.
- [SPHERE smart-TV testbed guide](https://docs.iot.sphere-testbed.net/smarttv/). HDMI source-isolation lead. Media are not bundled here.
- [SlopBro](https://github.com/throwaway96/slopbro/tree/21023d56ca424607bb03d2939609cc658c655fc7). Existing root method used before the ACR study. No rooting payload is redistributed.

GN's prepared attacker recording while offline is different from ordinary ACR automatically buffering uploads. Its voice-input text logs are also a separate subsystem. Our study does not adjudicate all GN/LG claims. GN later qualifies that the particular verbose RAM logs disappeared after complete power removal, with other retained logs not fully examined.
