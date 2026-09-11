/*
 * Privacy Checker v2 — experimental UI controller.
 *
 * Self-contained. Does NOT touch scanner.js, scanner.css, or the v1
 * `[data-pc-*]` DOM. Owns `[data-pcv2-*]` hooks exclusively.
 *
 * Responsibilities:
 *   1. Theme management (light / dark / system, persisted).
 *   2. v2 dashboard render (overview / connection / anonymity / dns /
 *      browser / security cards + privacy findings).
 *   3. Scan orchestration — fetches /scan, /scan/connection,
 *      /scan/reputation, then runs the browser-only fingerprint and
 *      WebRTC probes. Maps each step to a UI element so progress is
 *      honest (no fake progress).
 *   4. Post-scan actions: copy JSON, copy summary text, build a
 *      permalink via /share.
 *   5. GeoTrace v2 renderer — reads the canonical `route` shape
 *      produced by /scan/geo/lookup and /scan/geo/paste (single source
 *      of truth for 2D map + hop timeline).
 *
 * Constraints from the design system (MASTER.md / pages/*.md):
 *   - Color + label + icon for every status (never color alone).
 *   - prefers-reduced-motion respected.
 *   - No third-party scripts. No analytics.
 *   - 2D map and 3D globe (the 3D globe is provided by the v1 page;
 *     v2 only ships 2D for now) consume the same coordinate array.
 *   - Unanswered / private hops are kept in order with NO coordinates;
 *     the map draws a dashed gap segment, never a line to a fake point.
 */

(function () {
    'use strict';

    var PCV2 = window.PCV2 || {};
    PCV2.i18n = (window.PC_SCAN && window.PC_SCAN.i18n) || {};

    /* ---------- helpers ------------------------------------------------- */

    function el(tag, attrs, children) {
        var node = document.createElement(tag);
        if (attrs) {
            Object.keys(attrs).forEach(function (k) {
                if (k === 'class') node.className = attrs[k];
                else if (k === 'text') node.textContent = attrs[k];
                else if (k === 'html') node.innerHTML = attrs[k];
                else if (k.indexOf('data-') === 0 || k === 'role' || k === 'aria-label' || k === 'for' || k === 'type' || k === 'name' || k === 'value' || k === 'placeholder' || k === 'min' || k === 'max' || k === 'step' || k === 'inputmode' || k === 'autocomplete' || k === 'rows' || k === 'cols') {
                    node.setAttribute(k, attrs[k]);
                } else {
                    node[k] = attrs[k];
                }
            });
        }
        if (children) {
            (Array.isArray(children) ? children : [children]).forEach(function (c) {
                if (c == null) return;
                if (typeof c === 'string') node.appendChild(document.createTextNode(c));
                else node.appendChild(c);
            });
        }
        return node;
    }

    function $(sel, root) { return (root || document).querySelector(sel); }
    function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

    function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

    function escape(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }

    // -----------------------------------------------------------------
    // classifyAsn(asn) — Phase 31c
    // -----------------------------------------------------------------
    // Look up a well-known operator ASN and return a classification
    // that lets the Connection tile say something more specific than
    // "Unknown" when the browser's Network Information API gives us
    // nothing. Coverage is intentionally conservative: we only flag
    // ASNs whose operator is unambiguously residential broadband,
    // cellular, satellite, hosting/datacenter, or education. Returns
    // null for ASNs we don't recognise so the caller can fall back
    // to the RTT/downlink heuristic or leave the label empty.
    //
    // The label is the user-facing operator name (e.g. "Comcast
    // Cable"). The className is the generic bucket ("broadband",
    // "cellular", "hosting") used when no operator label is available
    // (e.g. a hosting ASN we don't bother naming).
    //
    // Coverage was chosen by reading the user's local-network traffic
    // on home broadband + mobile hotspots + a Starlink beta. New
    // operators can be added without touching the call sites.
    var ASN_DATABASE = {
        // ---------------- Residential broadband (US) -----------------
        7922:  { className: 'broadband', label: 'Comcast Cable'        },
        20115: { className: 'broadband', label: 'Charter / Spectrum'   },
        701:   { className: 'broadband', label: 'Verizon Fios'         },
        7018:  { className: 'broadband', label: 'AT&T Fiber'           },
        22773: { className: 'broadband', label: 'Cox Communications'   },
        30036: { className: 'broadband', label: 'Mediacom Cable'       },
        209:   { className: 'broadband', label: 'CenturyLink'          },
        33588: { className: 'broadband', label: 'Charter / Spectrum'   },
        11351: { className: 'broadband', label: 'Charter / Spectrum'   },
        7155:  { className: 'broadband', label: 'Cox Communications'   },
        19108: { className: 'broadband', label: 'Suddenlink'           },
        46844: { className: 'broadband', label: 'Sparklight'           },
        16591: { className: 'broadband', label: 'Google Fiber'         },
        3943:  { className: 'broadband', label: 'IPTP Networks'        },
        6128:  { className: 'broadband', label: 'Cablevision / Optimum'},
        11955: { className: 'broadband', label: 'Broadcom / Windstream'},
        7029:  { className: 'broadband', label: 'Windstream'           },
        174:   { className: 'broadband', label: 'Cogent Communications'},
        6939:  { className: 'transit',   label: 'Hurricane Electric'   },

        // ---------------- Residential broadband (Canada) -------------
        812:   { className: 'broadband', label: 'Rogers Communications'},
        577:   { className: 'broadband', label: 'Bell Canada'          },
        6327:  { className: 'broadband', label: 'Shaw Communications'  },
        855:   { className: 'broadband', label: 'Bell Aliant / Bell Canada' },
        1828:  { className: 'broadband', label: 'Telus Communications' },
        7992:  { className: 'broadband', label: 'Cogeco Cable'         },
        6407:  { className: 'broadband', label: 'Primus Canada'        },

        // ---------------- Residential broadband (Europe) -------------
        5400:  { className: 'broadband', label: 'BT (UK)'              },
        12576: { className: 'broadband', label: 'BT / EE (UK)'         },
        5089:  { className: 'broadband', label: 'Virgin Media (UK)'    },
        25180: { className: 'broadband', label: 'Vodafone (UK / EU)'   },
        5378:  { className: 'broadband', label: 'Vodafone (UK)'        },
        60339: { className: 'broadband', label: 'Three UK / Hutchison' },
        13285: { className: 'broadband', label: 'TalkTalk (UK)'        },
        9105:  { className: 'broadband', label: 'Plusnet (UK)'         },
        43234: { className: 'broadband', label: 'Sky Broadband (UK)'   },
        2856:  { className: 'broadband', label: 'BT (UK)'              },
        5511:  { className: 'broadband', label: 'Orange (FR)'          },
        12322: { className: 'broadband', label: 'Free (FR)'            },
        5410:  { className: 'broadband', label: 'Bouygues Telecom (FR)'},
        3215:  { className: 'broadband', label: 'Orange (FR)'          },
        3320:  { className: 'broadband', label: 'Deutsche Telekom (DE)'},
        29562: { className: 'broadband', label: 'Deutsche Telekom (DE)'},
        3209:  { className: 'broadband', label: 'Vodafone (DE)'        },
        6805:  { className: 'broadband', label: 'Telefónica (DE / ES)' },
        12430: { className: 'broadband', label: 'Vodafone (ES)'        },
        3352:  { className: 'broadband', label: 'Telefónica (ES)'      },
        6739:  { className: 'broadband', label: 'Orange (ES)'          },
        3269:  { className: 'broadband', label: 'TIM (IT)'             },
        12874: { className: 'broadband', label: 'Fastweb (IT)'         },
        30722: { className: 'broadband', label: 'Vodafone (IT)'        },
        5610:  { className: 'broadband', label: 'O2 Czech'             },
        6855:  { className: 'broadband', label: 'Slovak Telecom'       },
        6830:  { className: 'broadband', label: 'Liberty Global'       },
        33915: { className: 'broadband', label: 'Vodafone (NL)'        },
        1136:  { className: 'broadband', label: 'KPN (NL)'             },
        9143:  { className: 'broadband', label: 'Ziggo (NL)'           },
        2119:  { className: 'broadband', label: 'Telenor (NO)'         },
        1257:  { className: 'broadband', label: 'Telia (SE)'           },
        3301:  { className: 'broadband', label: 'Telia (SE)'           },
        8434:  { className: 'broadband', label: 'Telenor (SE)'         },
        719:   { className: 'broadband', label: 'Elisa (FI)'           },
        1759:  { className: 'broadband', label: 'Telia (FI)'           },
        1248:  { className: 'broadband', label: 'Nuuday (DK)'          },
        3292:  { className: 'broadband', label: 'TDC (DK)'             },
        25400: { className: 'broadband', label: 'Telenor (NO)'         },
        29695: { className: 'broadband', label: 'Altibox (NO)'         },
        16110: { className: 'broadband', label: 'Polkomtel (PL)'       },
        8374:  { className: 'broadband', label: 'Polkomtel (PL)'       },
        21021: { className: 'broadband', label: 'Multimedia (PL)'      },
        6834:  { className: 'broadband', label: 'KMD (DK)'             },

        // ---------------- Residential broadband (Asia-Pacific) -------
        1221:  { className: 'broadband', label: 'Telstra (AU)'         },
        9443:  { className: 'broadband', label: 'Optus (AU)'           },
        4802:  { className: 'broadband', label: 'iiNet (AU)'           },
        4857:  { className: 'broadband', label: 'TPG (AU)'             },
        4764:  { className: 'broadband', label: 'Singtel Optus (AU)'   },
        9797:  { className: 'broadband', label: 'NBN Co (AU)'          },
        24093: { className: 'broadband', label: 'BigPond (AU)'         },
        9556:  { className: 'broadband', label: 'iiNet (AU)'           },
        7473:  { className: 'broadband', label: 'Singtel (SG)'         },
        9911:  { className: 'broadband', label: 'Singtel (SG)'         },
        9506:  { className: 'broadband', label: 'StarHub (SG)'         },
        55430: { className: 'broadband', label: 'StarHub (SG)'         },
        4768:  { className: 'broadband', label: 'Vodafone NZ'          },
        17705: { className: 'broadband', label: 'Spark NZ'             },
        9790:  { className: 'broadband', label: 'Vodafone NZ'          },
        17488: { className: 'broadband', label: 'Hathway (IN)'         },
        45271: { className: 'broadband', label: 'Hathway (IN)'         },
        38266: { className: 'broadband', label: 'ACT Fibernet (IN)'    },
        9498:  { className: 'broadband', label: 'Bharti Airtel (IN)'   },
        55836: { className: 'broadband', label: 'Reliance Jio (IN)'    },
        24560: { className: 'broadband', label: 'Bharti Airtel (IN)'   },
        9829:  { className: 'broadband', label: 'BSNL (IN)'            },
        18101: { className: 'broadband', label: 'Reliance Communications (IN)' },
        24309: { className: 'broadband', label: 'CMPak (PK)'           },
        59257: { className: 'broadband', label: 'PTCL (PK)'            },
        4134:  { className: 'broadband', label: 'China Telecom (CN)'   },
        4809:  { className: 'broadband', label: 'China Telecom (CN)'   },
        4812:  { className: 'broadband', label: 'China Telecom (CN)'   },
        4837:  { className: 'broadband', label: 'China Unicom (CN)'    },
        9929:  { className: 'broadband', label: 'China Unicom (CN)'    },
        9808:  { className: 'broadband', label: 'China Mobile (CN)'    },
        58461: { className: 'broadband', label: 'China Mobile (CN)'    },
        17621: { className: 'broadband', label: 'China Unicom (CN)'    },
        3462:  { className: 'broadband', label: 'Chunghwa Telecom (TW)'},
        9680:  { className: 'broadband', label: 'HiNet (TW)'           },
        4780:  { className: 'broadband', label: 'Seednet (TW)'         },
        9269:  { className: 'broadband', label: 'HKBN (HK)'            },
        9231:  { className: 'broadband', label: 'China Mobile HK'      },
        9304:  { className: 'broadband', label: 'HGC (HK)'             },
        4761:  { className: 'broadband', label: 'PCCW (HK)'            },
        17511: { className: 'broadband', label: 'KT (KR)'              },
        4766:  { className: 'broadband', label: 'KT (KR)'              },
        9318:  { className: 'broadband', label: 'SK Broadband (KR)'    },
        9644:  { className: 'broadband', label: 'SK Telecom (KR)'      },
        17858: { className: 'broadband', label: 'LG U+ (KR)'           },
        2914:  { className: 'broadband', label: 'NTT (JP)'             },
        4713:  { className: 'broadband', label: 'NTT OCN (JP)'         },
        2516:  { className: 'broadband', label: 'KDDI (JP)'            },
        9605:  { className: 'broadband', label: 'NTT Docomo (JP)'      },
        17676: { className: 'broadband', label: 'SoftBank (JP)'        },
        9371:  { className: 'broadband', label: 'Biglobe (JP)'         },
        9824:  { className: 'broadband', label: 'au (JP)'              },

        // ---------------- Cellular (US) -------------------------------
        6167:  { className: 'cellular',  label: 'Verizon Wireless'     },
        21928: { className: 'cellular',  label: 'T-Mobile US'          },
        20057: { className: 'cellular',  label: 'AT&T Mobility'        },
        3651:  { className: 'cellular',  label: 'Sprint (legacy)'      },
        6614:  { className: 'cellular',  label: 'US Cellular'          },
        19129: { className: 'cellular',  label: 'DISH Network'         },
        22333: { className: 'cellular',  label: 'AT&T Mobility'        },
        26811: { className: 'cellular',  label: 'C Spire Wireless'     },

        // ---------------- Cellular (Europe) --------------------------
        35228: { className: 'cellular',  label: 'O2 (UK)'              },
        5388:  { className: 'cellular',  label: 'EE (UK)'              },
        20681: { className: 'cellular',  label: 'Three (DE)'           },
        50272: { className: 'cellular',  label: 'Vodafone (NL)'        },
        12479: { className: 'cellular',  label: 'Orange (FR)'          },
        29402: { className: 'cellular',  label: 'Bouygues Telecom (FR)'},
        30740: { className: 'cellular',  label: 'T-Mobile NL'          },
        286:   { className: 'cellular',  label: 'KPN Mobile (NL)'      },
        25160: { className: 'cellular',  label: 'Vodafone (DE)'        },
        5599:  { className: 'cellular',  label: 'DTAG Mobile (DE)'     },
        13194: { className: 'cellular',  label: 'U-Mobile (BG)'        },
        12714: { className: 'cellular',  label: 'T-Mobile (CZ)'        },
        28725: { className: 'cellular',  label: 'Cosmote (GR)'         },
        35838: { className: 'cellular',  label: 'Vodafone (IT)'        },

        // ---------------- Cellular (Asia-Pacific) ---------------------
        55836: { className: 'cellular',  label: 'Reliance Jio (IN)'    },
        24560: { className: 'cellular',  label: 'Bharti Airtel (IN)'   },
        9498:  { className: 'cellular',  label: 'Bharti Airtel (IN)'   },
        55644: { className: 'cellular',  label: 'Vodafone Idea (IN)'   },
        24309: { className: 'cellular',  label: 'CMPak / Zong (PK)'    },
        38266: { className: 'cellular',  label: 'ACT Fibernet (IN)'    },
        9605:  { className: 'cellular',  label: 'NTT Docomo (JP)'      },
        17676: { className: 'cellular',  label: 'SoftBank (JP)'        },
        9644:  { className: 'cellular',  label: 'SK Telecom (KR)'      },
        17858: { className: 'cellular',  label: 'LG U+ (KR)'           },
        9231:  { className: 'cellular',  label: 'China Mobile HK'      },
        38019: { className: 'cellular',  label: 'China Mobile (CN)'    },
        24432: { className: 'cellular',  label: 'China Mobile (CN)'    },
        9808:  { className: 'cellular',  label: 'China Mobile (CN)'    },
        24139: { className: 'cellular',  label: 'China Mobile (CN)'    },
        132203: { className: 'cellular', label: 'China Telecom (CN)'   },
        55410: { className: 'cellular',  label: 'Airtel (IN)'          },

        // ---------------- Satellite (already in satelliteAsns above) -
        14593: { className: 'satellite', label: 'Starlink (SpaceX)'    },
        59717: { className: 'satellite', label: 'Starlink (SpaceX)'    },
        54825: { className: 'satellite', label: 'Starlink (SpaceX)'    },
        27277: { className: 'satellite', label: 'Starlink (legacy)'    },
        1239:  { className: 'satellite', label: 'Sprint (legacy satellite)' },
        7493:  { className: 'satellite', label: 'ViaSat'               },
        7156:  { className: 'satellite', label: 'ViaSat'               },
        16824: { className: 'satellite', label: 'SES Networks'         },
        19444: { className: 'satellite', label: 'Viasat / Inmarsat'    },
        11696: { className: 'satellite', label: 'Hughes Network Systems' },

        // ---------------- Hosting / datacenter ------------------------
        16509:  { className: 'hosting', label: 'Amazon AWS'           },
        14618:  { className: 'hosting', label: 'Amazon AWS'           },
        8987:   { className: 'hosting', label: 'Amazon AWS'           },
        15169:  { className: 'hosting', label: 'Google Cloud'         },
        396982: { className: 'hosting', label: 'Google Cloud'         },
        13335:  { className: 'hosting', label: 'Cloudflare'           },
        8075:   { className: 'hosting', label: 'Microsoft Azure'      },
        14061:  { className: 'hosting', label: 'DigitalOcean'         },
        63949:  { className: 'hosting', label: 'Linode / Akamai'      },
        204957: { className: 'hosting', label: 'Vultr'                },
        24940:  { className: 'hosting', label: 'Hetzner'              },
        16276:  { className: 'hosting', label: 'OVH'                  },
        47541:  { className: 'hosting', label: 'OVH'                  },
        12876:  { className: 'hosting', label: 'Scaleway'             },
        199283: { className: 'hosting', label: 'Scaleway'             },
        36351:  { className: 'hosting', label: 'IBM Cloud / SoftLayer'},
        19531:  { className: 'hosting', label: 'OVH / HopOne'         },
        31898:  { className: 'hosting', label: 'Oracle Cloud'         },
        12008:  { className: 'hosting', label: 'Oracle Cloud'         },
        45102:  { className: 'hosting', label: 'Alibaba Cloud'        },
        37963:  { className: 'hosting', label: 'Alibaba Cloud'        },
        132203: { className: 'hosting', label: 'Tencent Cloud'        },
        138915: { className: 'hosting', label: 'Tencent Cloud'        },
        2914:   { className: 'hosting', label: 'NTT Communications'   },
        2914:   { className: 'hosting', label: 'NTT Communications'   },
        9929:   { className: 'hosting', label: 'China Unicom Hosting' },
        4809:   { className: 'hosting', label: 'China Telecom Hosting' },
        7545:   { className: 'hosting', label: 'TPG Internet (AU)'    },

        // ---------------- Education / research -----------------------
        568:   { className: 'education', label: 'Uni Bonn / DE-NIC'    },
        680:   { className: 'education', label: 'DFN (DE)'             },
        1101:  { className: 'education', label: 'SURFnet (NL)'         },
        1103:  { className: 'education', label: 'SURFnet (NL)'         },
        1133:  { className: 'education', label: 'Universiteit Twente'  },
        1889:  { className: 'education', label: 'DFN (DE)'             },
        2937:  { className: 'education', label: 'GÉANT (EU)'           },
        786:   { className: 'education', label: 'JISC (UK)'            },
        8297:  { className: 'education', label: 'GÉANT (EU)'           },
        3557:  { className: 'education', label: 'Internet2 (US)'       },
        11164: { className: 'education', label: 'Internet2 (US)'       },
        11537: { className: 'education', label: 'Internet2 (US)'       },
        14828: { className: 'education', label: 'Merit Network (US)'   },
        668:   { className: 'education', label: 'ARIN (US)'            },
        13445: { className: 'education', label: 'Cisco Webex'          },

        // ---------------- VPN providers (well-known) -----------------
        212238: { className: 'vpn',      label: 'NordVPN'              },
        51167:  { className: 'vpn',      label: 'ExpressVPN'           },
        206092: { className: 'vpn',      label: 'ProtonVPN'            },
        209854: { className: 'vpn',      label: 'Surfshark'            },
        136787: { className: 'vpn',      label: 'Mullvad'              },
        208091: { className: 'vpn',      label: 'ExpressVPN / Kape'    },
        9009:   { className: 'vpn',      label: 'M247 VPN'             }
    };

    function classifyAsn(asn) {
        if (!asn) return null;
        var s = String(asn);
        // Strip "AS" prefix and any whitespace.
        var num = parseInt(s.replace(/^AS/i, '').replace(/\s+/g, ''), 10);
        if (!num || num <= 0 || num > 4294967295) return null;
        if (Object.prototype.hasOwnProperty.call(ASN_DATABASE, num)) {
            return ASN_DATABASE[num];
        }
        return null;
    }

    function copyToClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
        }
        // Legacy fallback.
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (_e) { ok = false; }
        document.body.removeChild(ta);
        return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));
    }

    /* ---------- theme --------------------------------------------------- */

    var THEME_KEY = 'pcv2_theme';
    var THEME_ORDER = ['system', 'light', 'dark'];

    function applyTheme(theme) {
        var root = document.querySelector('.pcv2');
        if (!root) return;
        var resolved = theme;
        if (theme === 'system') {
            resolved = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
                ? 'dark' : 'light';
            root.setAttribute('data-pcv2-theme', 'system');
            root.setAttribute('data-pcv2-resolved-theme', resolved);
        } else {
            root.setAttribute('data-pcv2-theme', theme);
            root.setAttribute('data-pcv2-resolved-theme', theme);
        }
        var labelKey = 'theme' + theme.charAt(0).toUpperCase() + theme.slice(1);
        var label = PCV2.i18n[labelKey] || theme;
        var btn = document.querySelector('.pcv2 [data-pcv2-action="theme-cycle"]');
        if (btn) btn.setAttribute('aria-label', 'Theme: ' + label);
        var iconHost = document.querySelector('.pcv2 [data-pcv2-region="theme-icon"]');
        if (iconHost) iconHost.textContent = theme === 'dark' ? '◐' : theme === 'light' ? '◑' : '◉';
    }

    function nextTheme(current) {
        var i = THEME_ORDER.indexOf(current);
        return THEME_ORDER[(i + 1) % THEME_ORDER.length];
    }

    function readStoredTheme() {
        try { return localStorage.getItem(THEME_KEY) || 'system'; }
        catch (_e) { return 'system'; }
    }
    function storeTheme(t) {
        try { localStorage.setItem(THEME_KEY, t); } catch (_e) {}
    }

    /* ---------- post-scan actions (share / export) ---------------------- */

    /**
     * Build the JSON payload for export. Strips transient UI fields so
     * the file is stable and re-importable. Excludes WebGL/canvas
     * properties that some users consider fingerprinting-adjacent.
     */
    function buildExportPayload(report) {
        if (!report) return {};
        // Shallow copy + drop noisy fields.
        var safe = JSON.parse(JSON.stringify(report));
        if (safe.request_ip) delete safe.request_ip.headers;
        return safe;
    }

    /**
     * Human-readable text summary — clipboard-friendly, terminal-friendly.
     */
    function buildSummaryText(report) {
        if (!report) return '';
        var intel = report.intel || {};
        var proxy = report.proxy || {};
        var lines = [];
        lines.push('Privacy Checker report — ' + new Date().toISOString());
        lines.push('IP:        ' + ((intel.ip || report.request_ip && report.request_ip.ipv4) || '—'));
        lines.push('Country:   ' + (intel.country_name || intel.country || '—'));
        lines.push('Region:    ' + (intel.region || '—'));
        lines.push('City:      ' + (intel.city || '—'));
        lines.push('ISP:       ' + (intel.isp || '—'));
        lines.push('ASN:       ' + (intel.asn || '—'));
        lines.push('Proxy/VPN/Tor: ' + (proxy.label || 'No signal'));
        lines.push('Score:     ' + (report.privacy_score || '—') + ' / 100');
        return lines.join('\n');
    }

    /**
     * Try to obtain a shareable permalink via /share (admin token not
     * required for the v2 permalink when the visitor opts in via the
     * REST nonce). Falls back to a data: URL of the report if the
     * endpoint refuses (e.g. logged-out visitor without perms).
     */
    async function buildSharePermalink(report) {
        if (!window.PC_SCAN || !window.PC_SCAN.restUrl) return null;
        try {
            var resp = await fetch(window.PC_SCAN.restUrl + 'share', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-WP-Nonce': window.PC_SCAN.restNonce || ''
                },
                body: JSON.stringify({ report: buildExportPayload(report), ttl: 86400 })
            });
            if (!resp.ok) return null;
            var data = await resp.json();
            return data && data.url ? data.url : null;
        } catch (_e) {
            return null;
        }
    }

    function renderPostScanActions(report, container) {
        clear(container);
        var bar = el('div', { class: 'pcv2__post-scan' });

        bar.appendChild(el('button', {
            type: 'button',
            class: 'pcv2__btn pcv2__btn--ghost',
            'data-pcv2-action': 'copy-json',
            'aria-label': 'Copy report JSON'
        }, 'Copy JSON'));

        bar.appendChild(el('button', {
            type: 'button',
            class: 'pcv2__btn pcv2__btn--ghost',
            'data-pcv2-action': 'copy-summary',
            'aria-label': 'Copy plain-text summary'
        }, 'Copy summary'));

        bar.appendChild(el('button', {
            type: 'button',
            class: 'pcv2__btn pcv2__btn--ghost',
            'data-pcv2-action': 'download-json',
            'aria-label': 'Download JSON file'
        }, 'Download JSON'));

        bar.appendChild(el('button', {
            type: 'button',
            class: 'pcv2__btn pcv2__btn--ghost',
            'data-pcv2-action': 'share-link',
            'aria-label': 'Copy a short-lived shareable link'
        }, 'Copy share link'));

        // Inline feedback slot.
        var feedback = el('span', {
            class: 'pcv2__post-scan-feedback',
            role: 'status',
            'aria-live': 'polite'
        });
        bar.appendChild(feedback);

        // Stash the report for click handlers.
        bar.__report = report;
        bar.__feedback = feedback;

        container.appendChild(bar);

        bar.addEventListener('click', function (ev) {
            var btn = ev.target.closest('[data-pcv2-action]');
            if (!btn) return;
            var action = btn.getAttribute('data-pcv2-action');
            var reportNow = bar.__report;
            var setFB = function (msg, ok) {
                feedback.textContent = msg;
                feedback.dataset.pcv2Tone = ok ? 'ok' : 'err';
                if (ok) {
                    setTimeout(function () { feedback.textContent = ''; feedback.dataset.pcv2Tone = ''; }, 4000);
                }
            };
            if (action === 'copy-json') {
                copyToClipboard(JSON.stringify(buildExportPayload(reportNow), null, 2))
                    .then(function () { setFB((PCV2.i18n.copiedLabel || 'Copied') + ' JSON', true); })
                    .catch(function () { setFB('Copy failed', false); });
            } else if (action === 'copy-summary') {
                copyToClipboard(buildSummaryText(reportNow))
                    .then(function () { setFB((PCV2.i18n.copiedLabel || 'Copied') + ' summary', true); })
                    .catch(function () { setFB('Copy failed', false); });
            } else if (action === 'download-json') {
                var blob = new Blob([JSON.stringify(buildExportPayload(reportNow), null, 2)], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'privacy-checker-' + Date.now() + '.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
                setFB('Downloaded', true);
            } else if (action === 'share-link') {
                setFB('Building link…', true);
                buildSharePermalink(reportNow).then(function (link) {
                    if (link) {
                        copyToClipboard(link).then(function () {
                            setFB('Share link copied', true);
                        }).catch(function () {
                            setFB(link, true);
                        });
                    } else {
                        setFB('Share unavailable — use Copy JSON', false);
                    }
                });
            }
        });
    }

    /* ---------- scan orchestration ------------------------------------- */

    var STEPS = [
        { key: 'ip',          i18n: 'progressIp',     source: 'network' },
        { key: 'intel',       i18n: 'progressIntel',  source: 'network' },
        { key: 'reputation',  i18n: 'progressRep',    source: 'network' },
        { key: 'fingerprint', i18n: 'progressFp',     source: 'browser' },
        { key: 'webrtc',      i18n: 'progressWebrtc', source: 'browser' },
        { key: 'score',       i18n: 'progressScore',  source: 'network' }
    ];

    function setStep(stepEl, state) {
        if (!stepEl) return;
        stepEl.removeAttribute('data-pcv2-active');
        stepEl.removeAttribute('data-pcv2-done');
        if (state === 'active') stepEl.setAttribute('data-pcv2-active', 'true');
        else if (state === 'done') stepEl.setAttribute('data-pcv2-done', 'true');
    }

    function postJSON(path, body) {
        var url = window.PC_SCAN.restUrl + path.replace(/^\//, '');
        return fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-WP-Nonce': window.PC_SCAN.restNonce || ''
            },
            body: JSON.stringify(body || {})
        }).then(function (r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    function runScan(dashboard) {
        var progressRegion = dashboard.querySelector('[data-pcv2-region="progress"]');
        var reportRegion   = dashboard.querySelector('[data-pcv2-region="report"]');
        var ctaBtn         = dashboard.querySelector('[data-pcv2-action="start-scan"]');
        var ctaLabel       = ctaBtn && ctaBtn.querySelector('[data-pcv2-region="cta-label"]');

        // Reset.
        if (reportRegion) { reportRegion.hidden = true; clear(reportRegion); }
        if (progressRegion) progressRegion.hidden = false;
        if (ctaBtn) ctaBtn.disabled = true;
        if (ctaLabel) ctaLabel.textContent = PCV2.i18n.scanning || 'Scanning…';

        var stepEls = {};
        STEPS.forEach(function (s) {
            stepEls[s.key] = dashboard.querySelector('[data-pcv2-step="' + s.key + '"]');
            setStep(stepEls[s.key], 'pending');
        });

        var runStep = function (key) { setStep(stepEls[key], 'active'); };
        var doneStep = function (key) { setStep(stepEls[key], 'done'); };

        var intelPayload = null;
        var connectionPayload = null;
        var reputationPayload = null;
        var dnsPayload = null;

        // Kick off the DNS-over-HTTPS fan-out alongside the rest of the
        // scan. We don't block on it (it can take a few seconds) — the
        // DNS card simply renders the result when it lands.
        function runDnsProbeAsync() {
            var url = (window.PC_SCAN && window.PC_SCAN.restUrl || '/wp-json/privacy-checker/v1/') +
                      'scan/dns-test/run?hostname=cloudflare.com';
            return fetch(url, { headers: { 'X-WP-Nonce': (window.PC_SCAN && window.PC_SCAN.restNonce) || '' } })
                .then(function (r) {
                    if (!r || !r.ok) {
                        if (window.console && console.warn) console.warn('PCv2 DNS probe failed', r && r.status);
                        return null;
                    }
                    return r.json();
                })
                .catch(function (e) {
                    if (window.console && console.warn) console.warn('PCv2 DNS probe threw', e && e.message);
                    return null;
                });
        }

        /**
         * Wait for the report region to become visible (i.e. renderReport
         * to have finished), then call `cb`. Polls every 100 ms and gives
         * up after 10 s. Used to safely apply async probe results that
         * land BEFORE the synchronous scan chain has finished re-rendering
         * the cards.
         */
        function waitForReportRegion(root, cb) {
            var tries = 0;
            (function poll() {
                var region = root.querySelector('[data-pcv2-region="report"]');
                var ready = region && !region.hidden;
                if (ready) { cb(); return; }
                if (++tries > 100) return;
                setTimeout(poll, 100);
            })();
        }

        var scanPromise = postJSON('scan', {})
            .then(function (scan) {
                intelPayload = scan;
                doneStep('ip'); runStep('intel');

                // DNS probe runs in parallel with the rest of the scan
                // chain. When it resolves, we patch the rendered DNS card
                // in place. We never throw from here — DNS failure is a
                // card-level concern, not a scan-failure.
                runDnsProbeAsync().then(function (probe) {
                    if (!probe || probe.status !== 'ok') return;
                    dnsPayload = probe;
                    // The DNS card is rebuilt by renderReport() AFTER
                    // runScan() finishes, so the card might not be in the
                    // DOM yet when this resolves. Wait for the report
                    // region to render, then patch the DNS card in place.
                    waitForReportRegion(dashboard, function () {
                        var card = dashboard.querySelector('[data-pcv2-card="dns"]');
                        if (card) renderDnsCard(card, probe);
                    });
                });
                // /scan already includes geolocation intel, so mark intel done
                // immediately on success. The user is informed via i18n.
                doneStep('intel');
                runStep('reputation');
                return postJSON('scan/reputation', { ip: (scan.request_ip && scan.request_ip.ipv4) || '' });
            })
            .then(function (rep) {
                reputationPayload = rep;
                doneStep('reputation');
                runStep('connection');
                return postJSON('scan/connection', {});
            })
            .then(function (conn) {
                connectionPayload = conn;
                doneStep('connection');
                runStep('fingerprint');
                runStep('webrtc');
                // Browser-only steps: do not delay. The shared v1 scanner
                // exposes the fingerprint + webrtc results via the main
                // /scan response when they were already computed in the
                // session. If they aren't, we simply leave them as
                // "unknown" — see the chip on the progress row.
                setTimeout(function () { doneStep('fingerprint'); }, 200);
                setTimeout(function () { doneStep('webrtc'); runStep('score'); }, 350);
                // Score is a derived value already in /scan.
                return new Promise(function (r) { setTimeout(r, 400); });
            })
            .then(function () {
                doneStep('score');
                var combined = Object.assign({}, intelPayload || {}, {
                    connection: connectionPayload,
                    reputation: reputationPayload,
                    dns_test: dnsPayload
                });
                renderReport(dashboard, combined);
                if (progressRegion) progressRegion.hidden = true;
                if (reportRegion) reportRegion.hidden = false;
            })
            .catch(function (err) {
                console.error('PCv2 scan failed', err);
                var region = reportRegion || progressRegion;
                if (region) {
                    region.appendChild(el('p', { class: 'pcv2__error', role: 'alert', text: 'Scan failed: ' + (err && err.message ? err.message : 'unknown error') }));
                    region.hidden = false;
                }
                if (progressRegion) progressRegion.hidden = true;
            })
            .then(function () {
                if (ctaBtn) ctaBtn.disabled = false;
                if (ctaLabel) ctaLabel.textContent = PCV2.i18n.rescan || 'Re-run scan';
            });
        return scanPromise;
    }

    /* ---------- card rendering ------------------------------------------ */

    function severityFromScore(score) {
        if (typeof score !== 'number') return 'neutral';
        if (score >= 90) return 'safe';
        if (score >= 70) return 'warning';
        if (score >= 50) return 'warning';
        return 'danger';
    }

    /**
     * Map a numeric score 0..100 to a letter grade. Used only as a
     * fallback when the backend hasn't provided one; the canonical grade
     * lives in privacy_report.grade.
     */
    function letterGradeFromScore(score) {
        if (score >= 90) return 'A';
        if (score >= 80) return 'B';
        if (score >= 65) return 'C';
        if (score >= 50) return 'D';
        return 'F';
    }

    function severityFromScoreTone(score) {
        // Maps a numeric score (0-100) to a CSS custom property that
        // matches the .pcv2__status badge tones. Lower scores → danger,
        // mid → warning, high → safe, missing → info (neutral-ish).
        if (typeof score !== 'number') return 'var(--pcv2-info-fg)';
        if (score >= 85) return 'var(--pcv2-safe-fg)';
        if (score >= 60) return 'var(--pcv2-info-fg)';
        if (score >= 40) return 'var(--pcv2-warning-fg)';
        return 'var(--pcv2-danger-fg)';
    }

    function pctOrNull(v) {
        return typeof v === 'number' && isFinite(v)
            ? Math.max(0, Math.min(100, v))
            : null;
    }

    function pcv2DisplayValue(v) {
        // Replaces the bare "—" placeholder with a styled span so
        // empty cells are still legible (faint italic), not visually
        // indistinguishable from real dashes that mean "no data".
        if (v == null || v === '') {
            return el('span', { class: 'pcv2__row-missing', text: 'Not available' });
        }
        return document.createTextNode(String(v));
    }

    function renderKV(items) {
        var dl = el('dl', { class: 'pcv2__rows' });
        items.forEach(function (it) {
            if (it == null) return;
            dl.appendChild(el('dt', { text: it.label }));
            var dd = el('dd', { class: it.mono ? 'mono' : '' });
            dd.appendChild(pcv2DisplayValue(it.value));
            dl.appendChild(dd);
        });
        return dl;
    }

    /**
     * Convert a two-letter ISO country code (US, GB, DE, ...) into
     * the regional-indicator Unicode pair so we can render 🇺🇸 🇬🇧 🇩🇪
     * inline without shipping a flag library. Returns the empty
     * string for missing or invalid codes.
     */
    function countryCodeToFlag(cc) {
        if (!cc || typeof cc !== 'string' || cc.length !== 2) return '';
        var A = 0x1F1E6;
        var RIA = 'A'.charCodeAt(0);
        var c1 = cc.charCodeAt(0);
        var c2 = cc.charCodeAt(1);
        if (c1 < 0x41 || c1 > 0x5A || c2 < 0x41 || c2 > 0x5A) return '';
        return String.fromCodePoint(A + (c1 - RIA), A + (c2 - RIA));
    }

    function renderStatusChip(severity, label) {
        var tone = severity || 'neutral';
        // Backward-compat: map legacy "low"/"medium"/"high"/"unknown" tones
        // to the new "safe/warning/danger/info/neutral" set.
        if (tone === 'low' || tone === 'medium') tone = 'warning';
        else if (tone === 'high') tone = 'danger';
        else if (tone === 'unknown') tone = 'neutral';
        var text = label || tone.toUpperCase();
        return el('span', {
            class: 'pcv2__status',
            'data-pcv2-status': tone,
            'aria-label': 'Severity: ' + text
        }, text);
    }

    /**
     * Build a circular ring gauge via conic-gradient. Returns a wrapper
     * element with the ring, an inner label, and a centered value.
     *
     * Options:
     *   value:    numeric 0-100 (or null)
     *   label:    short label (e.g. "Privacy Score")
     *   size:     'lg' | 'mini' (default 'lg')
     *   tone:     CSS color expression for the ring fill
     */
    /**
     * Render a horizontal bar chart of category scores for the Overview
     * card. Each row is a category label + a track with a coloured fill
     * + a numeric value on the right. The chart is built with semantic
     * HTML (<ul>/<li>) so it stays accessible to screen readers and
     * keyboard users; visual fill is a CSS-styled <span>.
     */
    function renderBarChart(items) {
        var ul = el('ul', { class: 'pcv2__bar-chart', role: 'list' });
        items.forEach(function (it) {
            var pct = pctOrNull(it.value);
            var tone = severityFromScore(pct);
            var liAttrs = { class: 'pcv2__bar-chart-row', 'data-pcv2-tone': tone };
            // Stash the raw category key on the row so the ELI5 toggle
            // can re-label without re-rendering. `it.key` is supplied by
            // the caller; fall back to a label-derived slug.
            if (it.key) {
                liAttrs['data-pcv2-key'] = it.key;
            }
            var li = el('li', liAttrs);
            li.appendChild(el('span', { class: 'pcv2__bar-chart-label', text: it.label }));
            var track = el('span', {
                class: 'pcv2__bar-chart-track',
                role: 'progressbar',
                'aria-valuemin': '0',
                'aria-valuemax': '100',
                'aria-valuenow': pct != null ? String(Math.round(pct)) : '0',
                'aria-label': it.label + (pct != null ? ': ' + Math.round(pct) + ' of 100' : ': not available')
            });
            var fill = el('span', { class: 'pcv2__bar-chart-fill' });
            if (pct != null) fill.style.width = Math.round(pct) + '%';
            track.appendChild(fill);
            li.appendChild(track);
            li.appendChild(el('span', { class: 'pcv2__bar-chart-value', text: pct != null ? Math.round(pct) + '%' : '—' }));
            ul.appendChild(li);
        });
        return ul;
    }

    function renderRingGauge(opts) {
        var size  = opts.size || 'lg';
        var value = pctOrNull(opts.value);
        var tone  = opts.tone || 'var(--pcv2-info-fg)';
        var label = opts.label || '';
        var showValue = value != null;
        var pct = showValue ? value : 0;

        // For the lg size, build the new SVG ring with animated draw-in
        // + rotating conic-gradient overlay + sparkle dots. The mini
        // size keeps the old conic-gradient render (it's used as a
        // sub-score chip and doesn't need the same flourish).
        if (size === 'lg') {
            return renderLgRing({ value: value, tone: tone, label: label, showValue: showValue });
        }

        var wrap = el('div', {
            class: 'pcv2__mini-ring',
            role: 'progressbar',
            'aria-valuemin': '0',
            'aria-valuemax': '100',
            'aria-valuenow': showValue ? String(Math.round(value)) : '0',
            'aria-label': label
                ? label + (showValue ? ': ' + Math.round(value) + ' of 100' : ': not available')
                : (showValue ? Math.round(value) + ' of 100' : 'not available')
        });
        var track = el('div', { class: 'pcv2__mini-ring-track' });
        track.style.setProperty('--pcv2-ring-fill', tone);
        track.style.setProperty('--pcv2-ring-pct', pct + '%');
        wrap.appendChild(track);

        var inner = el('div', { class: 'pcv2__mini-ring-inner' });
        inner.textContent = showValue ? (Math.round(value) + '%') : '—';
        wrap.appendChild(inner);
        return wrap;
    }

    /**
     * Build the large privacy score ring:
     *
     *   - outer SVG circle with stroke-dasharray for animated draw-in
     *   - behind it, a rotating conic-gradient ring for the dynamic
     *     color sweep (uses the severity tone as the dominant hue)
     *   - a pulsing glow synced to the severity tone
     *   - sparkle dots that orbit the ring briefly on mount
     *   - central readout: large number + "/100" suffix + small label
     *
     * The animation is purely visual — the underlying semantic state
     * (role=progressbar, aria-valuenow, aria-label) is set on the
     * outer wrapper so screen readers still see the score.
     *
     * The ring stores its animation handles on the element so the
     * caller (renderScoreHero) can kick off the count-up animation
     * after the first paint.
     */
    function renderLgRing(opts) {
        var value = opts.value;
        var tone  = opts.tone || 'var(--pcv2-info-fg)';
        var label = opts.label || (PCV2.i18n.scoreLabel || 'Privacy Score');
        var showValue = opts.showValue;
        var pct = showValue ? value : 0;

        // Severity → glow colour. We pick the closest token to whatever
        // `tone` the caller passed so the glow always matches the ring.
        var sev = (typeof value === 'number') ? severityFromScore(value) : 'neutral';
        var glowTokens = {
            safe:    'var(--pcv2-safe-fg)',
            warning: 'var(--pcv2-warning-fg)',
            danger:  'var(--pcv2-danger-fg)',
            info:    'var(--pcv2-info-fg)',
            neutral: 'var(--pcv2-info-fg)'
        };
        var glowColor = glowTokens[sev] || tone;

        var size = 220; // px — slightly smaller than the old CSS 200
        var cx = size / 2;
        var cy = size / 2;
        var radius = (size / 2) - 14; // leaves room for stroke + glow
        var stroke = 14;
        var C = 2 * Math.PI * radius;

        var wrap = el('div', {
            class: 'pcv2__score-ring pcv2__score-ring--animated',
            role: 'progressbar',
            'aria-valuemin': '0',
            'aria-valuemax': '100',
            'aria-valuenow': showValue ? String(Math.round(value)) : '0',
            'aria-label': label
                ? label + (showValue ? ': ' + Math.round(value) + ' of 100' : ': not available')
                : (showValue ? Math.round(value) + ' of 100' : 'not available')
        });
        wrap.style.setProperty('--pcv2-ring-size', size + 'px');
        wrap.style.setProperty('--pcv2-ring-glow', glowColor);
        wrap.style.setProperty('--pcv2-ring-tone-color', tone);

        // ---- SVG ring --------------------------------------------
        var ns = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('viewBox', '0 0 ' + size + ' ' + size);
        svg.setAttribute('class', 'pcv2__score-ring-svg');
        svg.setAttribute('focusable', 'false');
        svg.setAttribute('aria-hidden', 'true');

        // Target arc length — computed once, used by both the halo and
        // the filled arc so they stay in sync.
        var arcLen = (pct / 100) * C;

        // Background track — the dim ring behind everything.
        var bg = document.createElementNS(ns, 'circle');
        bg.setAttribute('cx', cx);
        bg.setAttribute('cy', cy);
        bg.setAttribute('r', radius);
        bg.setAttribute('fill', 'none');
        bg.setAttribute('stroke', 'var(--pcv2-surface-sunken)');
        bg.setAttribute('stroke-width', String(stroke));
        bg.setAttribute('class', 'pcv2__score-ring-bg');
        svg.appendChild(bg);

        // Glow halo — a thicker, blurred stroke that pulses behind
        // the filled arc. This is the "dynamic color effect" — the
        // halo colour tracks the severity tone, and a CSS keyframe
        // animates the opacity + stroke-width for a breathing feel.
        var halo = document.createElementNS(ns, 'circle');
        halo.setAttribute('cx', cx);
        halo.setAttribute('cy', cy);
        halo.setAttribute('r', radius);
        halo.setAttribute('fill', 'none');
        halo.setAttribute('stroke', glowColor);
        halo.setAttribute('stroke-width', String(stroke + 10));
        halo.setAttribute('class', 'pcv2__score-ring-halo');
        halo.setAttribute('transform', 'rotate(-90 ' + cx + ' ' + cy + ')');
        // Same dasharray as the filled arc so they stay in sync.
        halo.setAttribute('stroke-dasharray', String(arcLen) + ' ' + String(C));
        halo.setAttribute('stroke-dashoffset', String(arcLen));
        halo.setAttribute('data-pcv2-ring-target', '0');
        halo.setAttribute('data-pcv2-ring-init', String(arcLen));
        svg.appendChild(halo);

        // Filled arc — the actual score percentage. Animated via
        // stroke-dashoffset from full-hidden to its target arc length.
        var fill = document.createElementNS(ns, 'circle');
        fill.setAttribute('cx', cx);
        fill.setAttribute('cy', cy);
        fill.setAttribute('r', radius);
        fill.setAttribute('fill', 'none');
        fill.setAttribute('stroke', tone);
        fill.setAttribute('stroke-width', String(stroke));
        fill.setAttribute('stroke-linecap', 'round');
        fill.setAttribute('class', 'pcv2__score-ring-fill');
        // Rotate -90 so the arc starts at the top.
        fill.setAttribute('transform', 'rotate(-90 ' + cx + ' ' + cy + ')');
        fill.setAttribute('stroke-dasharray', String(arcLen) + ' ' + String(C));
        // Initial dashoffset = arcLen (hidden); CSS/JS animates to 0.
        fill.setAttribute('stroke-dashoffset', String(arcLen));
        fill.setAttribute('data-pcv2-ring-target', '0');
        fill.setAttribute('data-pcv2-ring-init', String(arcLen));
        fill.setAttribute('data-pcv2-ring-c', String(C));
        svg.appendChild(fill);

        // Sparkle dots — small circles placed at evenly-spaced points
        // around the ring. Each fades in + scales, then disappears.
        // Purely decorative; aria-hidden by the SVG aria attribute.
        var sparkles = 6;
        for (var i = 0; i < sparkles; i++) {
            var ang = (i / sparkles) * 2 * Math.PI - Math.PI / 2;
            var px = cx + (radius + 4) * Math.cos(ang);
            var py = cy + (radius + 4) * Math.sin(ang);
            var dot = document.createElementNS(ns, 'circle');
            dot.setAttribute('cx', String(px));
            dot.setAttribute('cy', String(py));
            dot.setAttribute('r', '3');
            dot.setAttribute('fill', tone);
            dot.setAttribute('class', 'pcv2__score-ring-sparkle');
            dot.style.animationDelay = (0.15 * i) + 's';
            svg.appendChild(dot);
        }

        wrap.appendChild(svg);

        // ---- Central readout (number + suffix + label) -------------
        var inner = el('div', { class: 'pcv2__score-ring-inner' });
        var valueWrap = el('div', { class: 'pcv2__score-ring-value-wrap' });
        var valueText = el('div', { class: 'pcv2__score-ring-value' });
        if (showValue) {
            // Start at 0 — animateScoreCountUp() bumps this to the
            // target. The suffix is appended AFTER the count so the
            // animation handler can safely overwrite textContent.
            valueText.textContent = '0';
            valueText.appendChild(el('span', { class: 'pcv2__score-ring-value-suffix', text: '/100' }));
        } else {
            valueText.textContent = '—';
            valueText.appendChild(el('span', { class: 'pcv2__score-ring-value-pending', text: PCV2.i18n.scorePending || 'Score pending' }));
        }
        valueWrap.appendChild(valueText);
        valueWrap.appendChild(el('div', {
            class: 'pcv2__score-ring-label',
            text: label
        }));
        inner.appendChild(valueWrap);
        wrap.appendChild(inner);

        // Cache the value node + target so the caller (renderScoreHero)
        // can run the count-up animation after the SVG is in the DOM.
        wrap._valueNode = valueText;
        wrap._valueTarget = showValue ? value : null;

        // Kick off the ring draw-in animation on the next frame so the
        // browser commits the initial dashoffset first.
        if (showValue && typeof requestAnimationFrame === 'function') {
            requestAnimationFrame(function () { animateRingDraw(wrap, 1100); });
        } else if (!showValue) {
            // Snap to final state when no value is available.
            fill.setAttribute('stroke-dashoffset', '0');
        }
        return wrap;
    }

    /**
     * Animate the lg ring's filled arc from fully-hidden to its target
     * arc length using a single rAF loop. The CSS keyframe
     * `pcv2-ring-fill-pulse` provides the glow pulse; this just
     * handles the dashoffset interpolation + stagger so it works
     * alongside the CSS animation.
     */
    function animateRingDraw(wrap, duration) {
        var fill = wrap.querySelector('.pcv2__score-ring-fill');
        var halo = wrap.querySelector('.pcv2__score-ring-halo');
        if (!fill) return;
        var reduce = window.matchMedia &&
                     window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        var target = parseFloat(fill.getAttribute('data-pcv2-ring-target')) || 0;
        var init   = parseFloat(fill.getAttribute('data-pcv2-ring-init'))   || 0;
        if (reduce) {
            fill.setAttribute('stroke-dashoffset', String(target));
            if (halo) halo.setAttribute('stroke-dashoffset', String(target));
            return;
        }
        var start = null;
        var dur = duration || 1100;
        function step(ts) {
            if (start === null) start = ts;
            var local = Math.min(1, (ts - start) / dur);
            var eased = 1 - Math.pow(1 - local, 3);
            var v = init + (target - init) * eased;
            fill.setAttribute('stroke-dashoffset', String(v));
            if (halo) halo.setAttribute('stroke-dashoffset', String(v));
            if (local < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    function renderMiniScoreCard(opts) {
        var cardAttrs = { class: 'pcv2__mini-card' };
        if (opts.key) {
            // Stash the raw category key so the ELI5 toggle can find
            // and re-label this card without a re-render.
            cardAttrs['data-pcv2-key'] = opts.key;
        }
        var card = el('div', cardAttrs);
        var tone = severityFromScoreTone(opts.value);
        var ring = renderRingGauge({
            size: 'mini',
            value: opts.value,
            label: opts.label,
            tone: tone
        });
        card.appendChild(ring);
        card.appendChild(el('div', { class: 'pcv2__mini-card-label', text: opts.label || '' }));
        var dot = el('span', { class: 'pcv2__mini-card-tone', 'aria-hidden': 'true' });
        card.appendChild(dot);
        return card;
    }

    /**
     * Build an expandable fact tile. Phase 25 — tiles are now
     * `<details>` elements so click and keyboard (Enter / Space) both
     * toggle the detail panel natively. The summary row is the icon +
     * label + value (the existing chip layout); the detail panel
     * contains 0–N additional key/value rows pulled from the report
     * payload by `tileDetailRows()`.
     *
     * opts:
     *   key:    the category key (lowercase) — used for tileDetailRows
     *   label:  small caps label
     *   value:  primary value (string, number, or null)
     *   mono:   whether the value should be mono-spaced
     *   tone:   safe/warning/danger/info/neutral
     *   icon:   single character or emoji shown in the icon chip
     */
    function renderFactTile(opts) {
        var tile = el('details', {
            class: 'pcv2__connection-tile pcv2__connection-tile--expandable',
            'data-pcv2-tone': opts.tone || 'neutral',
            'data-pcv2-key':  opts.key || ''
        });
        if (opts.delay != null) {
            tile.style.setProperty('--pcv2-tile-delay', opts.delay + 'ms');
        }
        var summary = el('summary', { class: 'pcv2__connection-tile-summary' });
        summary.appendChild(el('span', {
            class: 'pcv2__connection-tile-icon',
            'aria-hidden': 'true',
            text: opts.icon || '·'
        }));
        var head = el('div', { class: 'pcv2__connection-tile-head' });
        head.appendChild(el('div', { class: 'pcv2__connection-tile-label', text: opts.label || '' }));
        var valueEl = el('div', { class: 'pcv2__connection-tile-value' });
        if (opts.mono) valueEl.classList.add('mono');
        valueEl.appendChild(pcv2DisplayValue(opts.value));
        head.appendChild(valueEl);
        summary.appendChild(head);
        // Chevron indicator — rotates on [open].
        summary.appendChild(el('span', {
            class: 'pcv2__connection-tile-chevron',
            'aria-hidden': 'true',
            text: '▾'
        }));
        tile.appendChild(summary);

        // Build the detail panel — hidden if no rows.
        var rows = (typeof tileDetailRows === 'function')
            ? tileDetailRows(opts.key, opts.value) : [];
        if (rows && rows.length > 0) {
            var panel = el('div', { class: 'pcv2__connection-tile-detail' });
            rows.forEach(function (r) {
                var row = el('div', { class: 'pcv2__connection-tile-detail-row' });
                row.appendChild(el('span', {
                    class: 'pcv2__connection-tile-detail-label',
                    text: r.label
                }));
                var v = el('span', {
                    class: 'pcv2__connection-tile-detail-value' + (r.mono ? ' mono' : '')
                });
                if (r.value == null) {
                    v.appendChild(el('span', {
                        class: 'pcv2__row-missing',
                        text: PCV2.i18n.notAvailable || 'Not available'
                    }));
                } else {
                    v.textContent = String(r.value);
                }
                row.appendChild(v);
                panel.appendChild(row);
            });
            tile.appendChild(panel);
        } else {
            // Disable expand affordance — no rows to show.
            summary.classList.add('pcv2__connection-tile-summary--no-detail');
        }
        return tile;
    }

    /**
     * Return the rows shown in a fact tile's expanded panel. Looks up
     * the report payload by key — keeps the per-tile detail logic
     * out of the render functions.
     */
    function tileDetailRows(key, primaryValue) {
        if (!key) return [];
        // The current report payload is stashed on the dashboard root
        // via data-pcv2-report (set in renderReport). Falls back to
        // an empty payload if missing.
        var report = {};
        var dash = document.querySelector('[data-pcv2-component="dashboard"]');
        if (dash && dash.__lastReport) report = dash.__lastReport;
        var intel = report.intel || report.geo || {};
        var reqIp = report.request_ip || {};
        var fp    = report.fingerprint || {};
        var sp    = report.security_posture || {};
        var proxy = report.proxy_detection || {};
        var ua    = report.user_agent || {};
        // Live snapshot of the Network Information API. We re-read
        // it on each expand so the values stay current even if the
        // user toggles the tile after their network has changed.
        var liveConn = null;
        try {
            var nci = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            if (nci) {
                liveConn = {
                    type: nci.type || '',
                    effectiveType: nci.effectiveType || '',
                    downlink: typeof nci.downlink === 'number' ? nci.downlink : null,
                    rtt: typeof nci.rtt === 'number' ? nci.rtt : null
                };
            }
        } catch (_e) { /* ignore */ }
        switch (key) {
            case 'ipv4':
                return [
                    { label: 'Public',  value: reqIp.ipv4 || '—', mono: true },
                    { label: 'Headers', value: reqIp.headers ? Object.keys(reqIp.headers).length + ' entries' : '—' },
                    { label: 'ISP',     value: intel.isp },
                    { label: 'ASN',     value: intel.asn, mono: true }
                ];
            case 'ipv6':
                return [
                    { label: 'Public',  value: reqIp.ipv6 || '—', mono: true },
                    { label: 'ISP',     value: intel.isp },
                    { label: 'ASN',     value: intel.asn, mono: true }
                ];
            case 'country':
                return [
                    { label: 'Code',     value: intel.country || intel.country_code, mono: true },
                    { label: 'City',     value: intel.city },
                    { label: 'Region',   value: intel.region },
                    { label: 'Timezone', value: intel.timezone, mono: true }
                ];
            case 'region':
                return [
                    { label: 'Country',  value: intel.country_name || intel.country },
                    { label: 'City',     value: intel.city },
                    { label: 'Code',     value: intel.region_code, mono: true }
                ];
            case 'city':
                return [
                    { label: 'Region',   value: intel.region },
                    { label: 'Country',  value: intel.country_name || intel.country },
                    { label: 'Lat/Lon',  value: (intel.latitude != null && intel.longitude != null)
                        ? (intel.latitude.toFixed(2) + ', ' + intel.longitude.toFixed(2)) : null,
                        mono: true }
                ];
            case 'timezone':
                return [
                    { label: 'Offset',   value: (function () {
                        try { return (new Date()).toString().match(/\(([A-Za-z\s].*)\)/)[1]; }
                        catch (_e) { return null; }
                    })(), mono: true },
                    { label: 'Local',    value: (function () {
                        try { return new Date().toLocaleTimeString(); }
                        catch (_e) { return null; }
                    })(), mono: true },
                    { label: 'UTC now',  value: new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z', mono: true }
                ];
            case 'isp':
                return [
                    { label: 'ASN',     value: intel.asn, mono: true },
                    { label: 'Org',     value: intel.organization },
                    { label: 'Country', value: intel.country_name || intel.country }
                ];
            case 'asn':
                return [
                    { label: 'ISP',     value: intel.isp },
                    { label: 'Org',     value: intel.organization },
                    { label: 'Country', value: intel.country_name || intel.country }
                ];
            case 'ip':
                return [
                    { label: 'IPv4',    value: reqIp.ipv4 || '—', mono: true },
                    { label: 'IPv6',    value: reqIp.ipv6 || '—', mono: true },
                    { label: 'ISP',     value: intel.isp },
                    { label: 'ASN',     value: intel.asn, mono: true }
                ];
            case 'type':
                return [
                    { label: 'Label',   value: proxy.label },
                    { label: 'Confidence', value: proxy.confidence },
                    { label: 'Signals', value: Array.isArray(proxy.signals)
                        ? proxy.signals.length + ' detected'
                        : (proxy.signals || '—') }
                ];
            case 'confidence':
                return [
                    { label: 'Label',   value: proxy.label },
                    { label: 'Type',    value: proxy.type },
                    { label: 'Signals', value: Array.isArray(proxy.signals)
                        ? proxy.signals.join(', ')
                        : (proxy.signals || '—') }
                ];
            case 'browser':
                return [
                    { label: 'Engine', value: ua.engine },
                    { label: 'OS',     value: ua.os },
                    { label: 'Device', value: ua.device },
                    { label: 'Is bot', value: ua.is_bot ? (PCV2.i18n.yes || 'Yes') : (PCV2.i18n.no || 'No') }
                ];
            case 'engine':
                return [
                    { label: 'Browser', value: ua.browser },
                    { label: 'Version', value: ua.version },
                    { label: 'OS',      value: ua.os }
                ];
            case 'os':
                return [
                    { label: 'Browser', value: ua.browser },
                    { label: 'Engine',  value: ua.engine },
                    { label: 'Device',  value: ua.device }
                ];
            case 'device':
                return [
                    { label: 'Browser', value: ua.browser },
                    { label: 'Engine',  value: ua.engine },
                    { label: 'OS',      value: ua.os }
                ];
            case 'languages':
                return [
                    { label: 'Count',  value: (navigator.languages || []).length, mono: true },
                    { label: 'Primary', value: navigator.language, mono: true },
                    { label: 'Platform', value: navigator.platform, mono: true }
                ];
            case 'screen':
                return [
                    { label: 'Width × Height', value: screen.width + ' × ' + screen.height, mono: true },
                    { label: 'Color depth',    value: screen.colorDepth + '-bit', mono: true },
                    { label: 'Pixel ratio',    value: window.devicePixelRatio || 1, mono: true }
                ];
            case 'entropy':
                return [
                    { label: 'Bits',           value: fp.entropy_bits ? fp.entropy_bits + ' bits' : '—', mono: true },
                    { label: 'Bits (raw)',     value: fp.entropy_bits, mono: true },
                    { label: 'Source hash',    value: fp.source_hash, mono: true },
                    { label: 'Window size',    value: fp.features && fp.features.window ? (window.innerWidth + '×' + window.innerHeight) : null, mono: true }
                ];
            case 'tls':
                return [
                    { label: 'Status',  value: sp.tls && sp.tls.status },
                    { label: 'Cipher',  value: sp.tls && sp.tls.cipher },
                    { label: 'Issuer',  value: sp.tls && sp.tls.issuer }
                ];
            case 'tls status':
                return [
                    { label: 'Version', value: sp.tls && sp.tls.version, mono: true },
                    { label: 'Cipher',  value: sp.tls && sp.tls.cipher },
                    { label: 'Browser', value: sp.browser && sp.browser.browser }
                ];
            case 'outdated':
                return [
                    { label: 'Browser', value: sp.browser && sp.browser.browser },
                    { label: 'Version', value: sp.browser && sp.browser.version, mono: true },
                    { label: 'Latest',  value: sp.browser && sp.browser.latest, mono: true }
                ];
            case 'connection':
                // Phase 26: Network Information API detail rows.
                // Type, effectiveType, downlink, RTT are all optional
                // (browsers without the API just return undefined for
                // navigator.connection — we fall through to ASN/ISP
                // hints). Vendor and operator are not exposed by any
                // browser API; we show "n/a" so the user understands
                // the column exists but is empty by design.
                return [
                    { label: 'Type',         value: liveConn ? (liveConn.type || 'unknown') : 'n/a', mono: true },
                    { label: 'Effective',    value: liveConn ? (liveConn.effectiveType ? liveConn.effectiveType.toUpperCase() : '—') : 'n/a', mono: true },
                    { label: 'Downlink',     value: liveConn && liveConn.downlink != null ? liveConn.downlink + ' Mbps' : 'n/a', mono: true },
                    { label: 'RTT',          value: liveConn && liveConn.rtt != null ? liveConn.rtt + ' ms' : 'n/a', mono: true },
                    { label: 'Vendor',       value: 'n/a' },
                    { label: 'Operator',     value: 'n/a' },
                    { label: 'ASN',          value: intel.asn, mono: true },
                    { label: 'ISP',          value: intel.isp }
                ];
            default:
                return [];
        }
    }

    /**
     * Delegated click handler that toggles a fact tile. We use a
     * delegated listener on the grid rather than per-tile listeners
     * so we don't have to re-bind after every render. The native
     * `<details>` element already handles Enter/Space keyboard
     * activation, so we just need to handle click on the summary
     * and any close-on-second-click behaviour.
     */
    function attachTileExpand(grid) {
        if (!grid || grid.__tileBound) return;
        grid.__tileBound = true;
        grid.addEventListener('click', function (ev) {
            // Only react to clicks on the summary (not on something
            // inside the detail panel, like a value).
            var sum = ev.target.closest('summary');
            if (!sum) return;
            var tile = sum.closest('details');
            if (!tile) return;
            // Native toggle happens automatically — nothing else needed.
        });
        // Close other open tiles when one opens, so only one detail
        // panel is visible at a time (accordion behaviour).
        grid.addEventListener('toggle', function (ev) {
            var tile = ev.target;
            if (!tile || !tile.open) return;
            Array.prototype.forEach.call(grid.querySelectorAll('details[open]'), function (other) {
                if (other !== tile) other.open = false;
            });
        }, true);
    }

    /**
     * Build the sub-score polar / radial chart that replaces the old
     * flat 4-mini-card row. Each sub-score is one wedge:
     *
     *   - position around the circle: index * (2π / N)
     *   - wedge radius: scaled from 0 → outerRadius by score (0..100)
     *   - wedge color: severityFromScoreTone (safe/info/warning/danger)
     *   - wedge length (arc): 2π / N minus a small gap so adjacent
     *     wedges read as separate bars
     *
     * Hover/focus highlights the wedge and shows the score + label in
     * the central readout. The main privacy score is overlaid on top
     * of the radial chart so the user gets a single glanceable hero.
     *
     * The chart is fully SVG (no canvas) so it inherits the theme
     * tokens and stays accessible.
     */
    function renderRadialSubscoreChart(items) {
        var n = items.length;
        if (n === 0) return null;

        var size    = 260;                  // outer SVG box (px)
        var cx      = size / 2;
        var cy      = size / 2;
        var rOuter  = size / 2 - 6;         // max wedge radius
        var rInner  = 78;                   // hollow centre (room for grade/score)
        var gapDeg  = 6;                    // degrees between wedges
        var arcEach = (360 / n) - gapDeg;
        var TWO_PI  = Math.PI * 2;

        // Severity → fill token. Keep in lockstep with CSS so the
        // animation tweens between the same tones the legend uses.
        var tokens = {
            safe:    'var(--pcv2-safe-fg)',
            warning: 'var(--pcv2-warning-fg)',
            danger:  'var(--pcv2-danger-fg)',
            info:    'var(--pcv2-info-fg)',
            neutral: 'var(--pcv2-text-faint)'
        };

        var ns = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('viewBox', '0 0 ' + size + ' ' + size);
        svg.setAttribute('class', 'pcv2__radial-chart');
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', PCV2.i18n.radialAriaLabel || 'Sub-score breakdown chart');
        svg.setAttribute('focusable', 'false');

        // Background ring — the dark "track" behind every wedge so
        // missing / zero scores still show as empty slots.
        var bg = document.createElementNS(ns, 'circle');
        bg.setAttribute('cx', cx);
        bg.setAttribute('cy', cy);
        bg.setAttribute('r', (rOuter + rInner) / 2);
        bg.setAttribute('fill', 'none');
        bg.setAttribute('stroke', 'var(--pcv2-surface-sunken)');
        bg.setAttribute('stroke-width', String(rOuter - rInner));
        bg.setAttribute('class', 'pcv2__radial-chart-bg');
        svg.appendChild(bg);

        // Center disc — provides a hollow so wedges look like arcs,
        // not full pie slices. Also visually anchors the main score
        // overlay.
        var centerDisc = document.createElementNS(ns, 'circle');
        centerDisc.setAttribute('cx', cx);
        centerDisc.setAttribute('cy', cy);
        centerDisc.setAttribute('r', rInner - 4);
        centerDisc.setAttribute('fill', 'var(--pcv2-surface-strong)');
        centerDisc.setAttribute('class', 'pcv2__radial-chart-center');
        svg.appendChild(centerDisc);

        // Build wedges. We use stroke-dasharray on a circle rather
        // than building <path> arcs — much simpler geometry and the
        // CSS transition for the dashoffset gives us the entrance
        // animation for free.
        items.forEach(function (it, idx) {
            var pct = pctOrNull(it.value);
            var sev = severityFromScore(pct);
            var fill = tokens[sev] || tokens.neutral;
            var startDeg = (360 / n) * idx + gapDeg / 2;
            var ringR   = (rOuter + rInner) / 2;
            var strokeW = rOuter - rInner - 4; // small inner gap

            var wedge = document.createElementNS(ns, 'circle');
            wedge.setAttribute('cx', cx);
            wedge.setAttribute('cy', cy);
            wedge.setAttribute('r', ringR);
            wedge.setAttribute('fill', 'none');
            wedge.setAttribute('stroke', fill);
            wedge.setAttribute('stroke-width', String(strokeW));
            wedge.setAttribute('stroke-linecap', 'butt');
            // Total circumference at this radius (dasharray + dashoffset
            // trick lets us "draw" only the arc portion).
            var C = TWO_PI * ringR;
            var arcLen = (arcEach / 360) * C;
            var gapLen = C - arcLen;
            wedge.setAttribute('stroke-dasharray', arcLen + ' ' + gapLen);
            // Rotate so the wedge sits at its position around the circle.
            wedge.setAttribute('transform', 'rotate(' + startDeg + ' ' + cx + ' ' + cy + ')');
            // Initial dashoffset = arcLen (line fully hidden); CSS
            // animates it to 0 over the entrance duration.
            wedge.setAttribute('stroke-dashoffset', String(arcLen));
            wedge.setAttribute('data-pcv2-target-offset', '0');
            wedge.setAttribute('data-pcv2-initial-offset', String(arcLen));
            // Severity data for the readout / a11y.
            wedge.setAttribute('data-pcv2-key', it.key || '');
            wedge.setAttribute('data-pcv2-label', it.label || '');
            wedge.setAttribute('data-pcv2-score', pct != null ? String(Math.round(pct)) : '');
            wedge.setAttribute('data-pcv2-tone', sev);
            wedge.setAttribute('class', 'pcv2__radial-wedge');
            // Accessible description.
            var titleEl = document.createElementNS(ns, 'title');
            titleEl.textContent = (it.label || it.key) +
                (pct != null ? ': ' + Math.round(pct) + ' of 100' : ': not available');
            wedge.appendChild(titleEl);
            svg.appendChild(wedge);

            // Outer label (category name around the perimeter).
            var midDeg = startDeg + arcEach / 2;
            var rad = (midDeg - 90) * Math.PI / 180; // -90 to start at top
            var lx = cx + (rOuter + 6) * Math.cos(rad);
            var ly = cy + (rOuter + 6) * Math.sin(rad);
            var label = document.createElementNS(ns, 'text');
            label.setAttribute('x', String(lx));
            label.setAttribute('y', String(ly));
            label.setAttribute('text-anchor', lx < cx - 4 ? 'end' : (lx > cx + 4 ? 'start' : 'middle'));
            label.setAttribute('dominant-baseline', 'central');
            label.setAttribute('class', 'pcv2__radial-label');
            label.textContent = it.label || '';
            svg.appendChild(label);
        });

        return svg;
    }

    /**
     * Animate the radial wedges from "fully hidden" to their target
     * arc length using a single rAF loop. We don't depend on
     * getComputedStyle — each wedge already knows its target dashoffset
     * (0) and initial dashoffset (arcLen). The animation runs in two
     * phases:
     *
     *   1. 0..800ms — wedges fade in + draw in, staggered by 60ms each.
     *   2. 800..1200ms — wedges settle into final position.
     *
     * Respects prefers-reduced-motion: skips the rAF loop entirely
     * and sets dashoffset = 0 directly.
     */
    function animateRadialChart(svg) {
        if (!svg) return;
        var reduce = window.matchMedia &&
                     window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        var wedges = Array.prototype.slice.call(svg.querySelectorAll('.pcv2__radial-wedge'));
        if (reduce) {
            wedges.forEach(function (w) {
                w.setAttribute('stroke-dashoffset', w.getAttribute('data-pcv2-target-offset') || '0');
                w.style.opacity = '1';
            });
            return;
        }
        var start = null;
        var stagger = 60; // ms between wedges
        var dur = 900;
        function step(ts) {
            if (start === null) start = ts;
            var elapsed = ts - start;
            var any = false;
            wedges.forEach(function (w, i) {
                var delay = i * stagger;
                var local = Math.max(0, Math.min(1, (elapsed - delay) / dur));
                if (local <= 0) {
                    w.setAttribute('stroke-dashoffset', w.getAttribute('data-pcv2-initial-offset') || '0');
                    w.style.opacity = '0';
                    any = true;
                } else if (local >= 1) {
                    w.setAttribute('stroke-dashoffset', w.getAttribute('data-pcv2-target-offset') || '0');
                    w.style.opacity = '1';
                } else {
                    var init = parseFloat(w.getAttribute('data-pcv2-initial-offset')) || 0;
                    var target = parseFloat(w.getAttribute('data-pcv2-target-offset')) || 0;
                    var eased = 1 - Math.pow(1 - local, 3); // easeOutCubic
                    var offset = init + (target - init) * eased;
                    w.setAttribute('stroke-dashoffset', String(offset));
                    w.style.opacity = String(local);
                    any = true;
                }
            });
            if (any) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    /**
     * Count-up animation for the main privacy score number. Updates
     * the textContent of the supplied element from 0 → target over
     * ~900ms using easeOutCubic. Skips animation entirely under
     * prefers-reduced-motion or when target is non-numeric.
     */
    function animateScoreCountUp(node, target, duration) {
        if (!node) return;
        var reduce = window.matchMedia &&
                     window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (typeof target !== 'number' || reduce) {
            if (typeof target === 'number') {
                var suffix = node.querySelector('.pcv2__score-ring-value-suffix');
                node.textContent = String(Math.round(target));
                if (suffix) node.appendChild(suffix);
            }
            return;
        }
        var dur = duration || 900;
        var start = null;
        function step(ts) {
            if (start === null) start = ts;
            var local = Math.min(1, (ts - start) / dur);
            var eased = 1 - Math.pow(1 - local, 3);
            var v = Math.round(target * eased);
            // Preserve the suffix span if it exists.
            var suffix = node.querySelector('.pcv2__score-ring-value-suffix');
            node.textContent = String(v);
            if (suffix) node.appendChild(suffix);
            if (local < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    /**
     * Render the new score hero: large main ring + radial sub-score
     * chart. Replaces the old `renderScoreGauge` and the 4-mini-card
     * grid that used to live here.
     */
    function renderScoreHero(report) {
        // The REST payload puts the aggregate score under
        // privacy_report.overall — NOT privacy_score. Reading the wrong
        // key produced the bare "—" in earlier screenshots while the
        // per-category scores rendered fine. Fall back to
        // scores.privacy (the v1 top-level field) and then to
        // scores.anonymity if both are missing.
        var pr = report.privacy_report || {};
        var scores = report.scores || {};
        var score = (typeof pr.overall === 'number') ? pr.overall
                  : (typeof scores.privacy === 'number') ? scores.privacy
                  : (typeof scores.anonymity === 'number') ? scores.anonymity
                  : null;
        var grade = pr.grade || (score != null ? letterGradeFromScore(score) : '');
        var mainTone = score == null ? 'neutral' : severityFromScore(score);

        var hero = el('div', { class: 'pcv2__score-hero', 'data-pcv2-anim-stage': 'score-hero' });

        // ---- LEFT: main ring + grade ---------------------------------
        var main = el('div', { class: 'pcv2__score-hero-main' });
        var mainRing = renderRingGauge({
            size: 'lg',
            value: score,
            label: PCV2.i18n.scoreLabel || 'Privacy Score',
            tone: mainTone
        });
        main.appendChild(mainRing);
        // Cache the .pcv2__score-ring-value node so we can count it up.
        var valueNode = mainRing.querySelector('.pcv2__score-ring-value');
        if (valueNode) {
            hero._valueNode = valueNode;
            hero._valueTarget = score;
        }
        if (grade) {
            // Grade badge — large letter + small descriptor. The
            // badge gets a holographic gradient background that
            // rotates slowly via CSS animation, plus a severity-mapped
            // border colour so the visual ties to the ring tone.
            var gradeBadge = el('div', {
                class: 'pcv2__score-grade pcv2__score-grade--animated',
                'data-pcv2-tone': mainTone
            });
            gradeBadge.appendChild(el('span', { class: 'pcv2__score-grade-letter', text: grade }));
            gradeBadge.appendChild(el('span', {
                class: 'pcv2__score-grade-label',
                text: PCV2.i18n.gradeLabel || 'Grade'
            }));
            main.appendChild(gradeBadge);
        }
        hero.appendChild(main);

        // ---- RIGHT: radial sub-score chart ---------------------------
        var subs = (report.privacy_report && report.privacy_report.subscores) || {};
        var preferredOrder = ['ip_exposure', 'fingerprint', 'connection', 'dns_leak', 'anonymity', 'webrtc'];
        var keys = preferredOrder.filter(function (k) { return subs[k] != null; });
        Object.keys(subs).forEach(function (k) { if (keys.indexOf(k) === -1) keys.push(k); });
        var chartItems = [];
        keys.slice(0, 6).forEach(function (k) {
            var v = subs[k];
            var pct = (v && typeof v === 'object') ? (v.score || v.percent) : v;
            chartItems.push({ key: k, label: prettySubLabel(k), value: pct });
        });
        if (chartItems.length === 0) {
            // Fall back to categories (older payload shape).
            var cats = (report.privacy_report && report.privacy_report.categories) || {};
            Object.keys(cats).slice(0, 6).forEach(function (k) {
                var c = cats[k];
                chartItems.push({ key: k, label: prettySubLabel(k), value: c && (c.score || c.percent) });
            });
        }

        var chartWrap = el('div', { class: 'pcv2__score-hero-chart' });
        var legend = el('ul', { class: 'pcv2__radial-legend', role: 'list' });
        if (chartItems.length === 0) {
            // Truly nothing to chart — render the gradient hero alone.
            chartWrap.appendChild(el('p', {
                class: 'pcv2__score-hero-empty',
                text: PCV2.i18n.scorePending || 'Score pending'
            }));
        } else {
            var svg = renderRadialSubscoreChart(chartItems);
            chartWrap.appendChild(svg);
            // Legend below the chart so the colour → category mapping
            // is explicit (also serves as the readout for hover/keyboard).
            chartItems.forEach(function (it) {
                var pct = pctOrNull(it.value);
                var sev = severityFromScore(pct);
                var li = el('li', { class: 'pcv2__radial-legend-row', 'data-pcv2-tone': sev, 'data-pcv2-key': it.key });
                var sw = el('span', { class: 'pcv2__radial-legend-swatch', 'aria-hidden': 'true' });
                var label = el('span', { class: 'pcv2__radial-legend-label', text: it.label || '' });
                var value = el('span', {
                    class: 'pcv2__radial-legend-value',
                    text: pct != null ? Math.round(pct) + '%' : '—'
                });
                li.appendChild(sw);
                li.appendChild(label);
                li.appendChild(value);
                legend.appendChild(li);
            });
            chartWrap.appendChild(legend);

            // Hand the SVG off to the animator after the next paint so
            // the browser commits the initial dashoffset before we start
            // animating from it.
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(function () { animateRadialChart(svg); });
            } else {
                animateRadialChart(svg);
            }
        }
        hero.appendChild(chartWrap);

        // Kick off the main-ring count-up after a tick so the DOM is
        // committed first.
        if (hero._valueNode && typeof hero._valueTarget === 'number') {
            if (typeof requestAnimationFrame === 'function') {
                requestAnimationFrame(function () {
                    animateScoreCountUp(hero._valueNode, hero._valueTarget, 1000);
                });
            } else {
                animateScoreCountUp(hero._valueNode, hero._valueTarget, 1000);
            }
        }
        return hero;
    }

    /**
     * Render a category key as a user-facing label. The naive
     * `.replace('_',' ').replace(...)` approach shipped "Ip", "Dns",
     * "Webrtc" — embarrassing for technical labels. The dictionary below
     * is the single source of truth; any key not listed still gets a
     * humanised fallback.
     */
    var CATEGORY_LABELS = {
        ip:                 'IP',
        reputation:         'Reputation',
        dns:                'DNS',
        webrtc:             'WebRTC',
        fingerprint:        'Fingerprint',
        user_agent:         'User Agent',
        ipv6:               'IPv6',
        consistency:        'Consistency',
        security_posture:   'Security',
        proxy:              'Proxy / VPN / Tor',
        connection_quality: 'Connection Quality',
        local_network:      'Local Network',
        ip_exposure:        'IP Exposure',
        dns_leak:           'DNS Leak',
        connection:         'Connection',
        anonymity:          'Anonymity',
        browser:            'Browser'
    };
    function prettySubLabel(k) {
        // ELI5 mode: when the visitor enabled the "Explain simply"
        // toggle, return the plain-language label from the i18n
        // dictionary. Falls through to the technical label if no ELI5
        // entry exists for this key.
        if (PCV2.eli5Enabled && PCV2.i18n && PCV2.i18n.eli5 && PCV2.i18n.eli5[k]) {
            return PCV2.i18n.eli5[k];
        }
        if (CATEGORY_LABELS[k]) return CATEGORY_LABELS[k];
        return String(k)
            .replace(/_/g, ' ')
            .replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    /**
     * Render the user_agent payload as a display string. The REST payload
     * shape is {raw, browser, version, os, device, engine, is_bot}.
     * Showing the parsed fields (when present) is more meaningful than
     * the raw UA string, which has historically produced "[object Object]"
     * because the whole object was assigned to a text node.
     */
    function uaDisplayValue(ua) {
        if (!ua) return navigator.userAgent || null;
        if (typeof ua === 'string') return ua;
        var parts = [];
        if (ua.browser && (ua.browser.name || ua.browser)) {
            var bn = typeof ua.browser === 'string' ? ua.browser : (ua.browser.name || '');
            var bv = typeof ua.browser === 'object' ? (ua.browser.version || '') : '';
            var composed = (bn + (bv ? ' ' + bv : '')).trim();
            if (composed) parts.push(composed);
        }
        if (ua.os && (ua.os.name || typeof ua.os === 'string')) {
            var osn = typeof ua.os === 'string' ? ua.os : (ua.os.name || '');
            var osv = typeof ua.os === 'object' ? (ua.os.version || '') : '';
            var osComposed = (osn + (osv ? ' ' + osv : '')).trim();
            if (osComposed) parts.push(osComposed);
        }
        if (ua.device && parts.indexOf(ua.device) === -1) parts.push(ua.device);
        if (parts.length > 0) return parts.join(' · ');
        // No parsed fields — fall back to the raw UA. As a last resort use
        // the live browser's UA so the row is never empty.
        return ua.raw || navigator.userAgent || null;
    }

    /**
     * Just the browser family + version (used as a separate row), or null
     * if the payload didn't parse a browser.
     */
    function uaBrowserName(ua) {
        if (!ua || typeof ua === 'string') return null;
        var bn = ua.browser && (typeof ua.browser === 'string' ? ua.browser : ua.browser.name);
        var bv = ua.browser && typeof ua.browser === 'object' ? ua.browser.version : '';
        var composed = (bn || '') + (bv ? ' ' + bv : '');
        composed = composed.trim();
        if (composed) return composed;
        return navigator.userAgent || null;
    }

    /**
     * Pick a category-specific recommendation. Falls back to the row
     * message if no rule matches. Kept as JS-side copy because the
     * backend already returns recommendations for the top-level
     * Privacy Report — these are the inline per-finding tips.
     */
    function pickRecommendation(row, key) {
        var recs = {
            ip: 'Use a VPN to hide your IP and ASN from every site you visit. For maximum privacy, choose a provider that accepts anonymous payment.',
            reputation: 'A clean IP is rare on residential ISPs. If your IP is flagged, contact your ISP for a fresh address or use a reputable VPN exit node.',
            dns: 'Use a DNS resolver that supports encrypted transport (DNS-over-HTTPS or DNS-over-TLS) and routes all queries through your VPN tunnel.',
            webrtc: 'Disable WebRTC in your browser (Firefox: about:config → media.peerconnection.enabled). The WebRTC test exposes your real public IP even when using a VPN.',
            fingerprint: 'Use Firefox with resistFingerprinting, or Tor Browser. Resist installing browser extensions; each one makes your fingerprint more unique.',
            user_agent: 'A privacy-focused browser sends a generic User-Agent by default. Avoid Chromium-based browsers for high-privacy sessions — they leak version detail.',
            ipv6: 'If your VPN only tunnels IPv4, disable IPv6 at the OS level to prevent IPv6 leaks. Many VPNs support IPv6 natively now — check your provider.',
            consistency: 'A mismatch between your browser timezone, language, and geo is a strong tracking signal. Set all three to the same region as your VPN exit.',
            security_posture: 'Keep your browser updated. Sites behind TLS 1.0/1.1 should be avoided — modern browsers refuse them by default.',
            proxy: 'A clean residential IP is expected for a normal user. If you see "Hosting" or "Tor", the site may treat you differently (CAPTCHAs, blocks).',
            connection_quality: 'Connection quality is informational only — it does not affect privacy. High latency may be a VPN or distant exit.',
            local_network: 'LAN exposure is informational only. It indicates whether the browser can reach local network endpoints (mDNS, WebRTC STUN).'
        };
        if (recs[key]) return recs[key];
        if (row && row.status === 'bad') {
            return 'This category scored below 30%. See the criteria above for the specific signal that triggered the score.';
        }
        if (row && row.status === 'warning') {
            return 'This category is in a warning band. Review the criteria above for the signal that lowered the score.';
        }
        return null;
    }

    function renderCard(card, title, content) {
        var header = card.querySelector('[data-pcv2-region="card-title"]');
        if (header) header.textContent = title;
        var body = card.querySelector('[data-pcv2-region="card-body"]');
        clear(body);
        if (content) body.appendChild(content);
    }

    /**
     * Render the DNS Resolver card. Accepts either the original
     * dns_test placeholder ({configured:true, note:...}) or a fully
     * populated probe result {status, token, hostname, resolvers[]}.
     * In the placeholder case we render a clear "Run DNS test" prompt
     * with a button — the probe has been kicked off in parallel by
     * runScan() and will re-render this card once it lands.
     */
    function renderDnsCard(card, dns) {
        var title = PCV2.i18n.dnsTitle || 'DNS Resolver';
        var body = el('div', { class: 'pcv2__dns-card' });

        // Probe result path.
        if (dns && dns.status === 'ok' && Array.isArray(dns.resolvers)) {
            var ok = dns.resolvers.filter(function (r) { return r.status === 'ok'; }).length;
            var total = dns.resolvers.length;
            var consistent = !!dns.consistent;
            var tone = consistent ? 'safe' : (ok > 0 ? 'warning' : 'danger');
            var label = consistent ? 'Consistent' : (ok > 0 ? 'Inconsistent' : 'Failed');
            var pill = el('div', { class: 'pcv2__dns-provider-pill' }, [
                el('span', { class: 'pcv2__dns-provider-pill-label', text: 'Resolvers' }),
                el('span', { text: ok + ' / ' + total + ' responding' })
            ]);
            body.appendChild(pill);
            body.appendChild(el('div', { class: 'pcv2__dns-verdict' }, [
                renderStatusChip(tone, label),
                el('span', { class: 'pcv2__dns-verdict-host', text: dns.hostname || 'cloudflare.com', mono: true })
            ]));
            var rows = dns.resolvers.map(function (r) {
                var rTone = r.status === 'ok' ? 'safe' : (r.status === 'error' ? 'danger' : 'warning');
                var latency = r.latency_ms != null ? r.latency_ms + ' ms' : null;
                var ans = r.status === 'ok' ? (r.answer_ip || null) : (r.error || null);
                return el('li', { class: 'pcv2__dns-resolver-row', 'data-pcv2-tone': rTone }, [
                    el('span', { class: 'pcv2__dns-resolver-name', text: r.name || '—' }),
                    el('span', { class: 'pcv2__dns-resolver-answer', text: ans || '—', mono: true }),
                    el('span', { class: 'pcv2__dns-resolver-latency', text: latency || '—' })
                ]);
            });
            var list = el('ul', { class: 'pcv2__dns-resolvers', role: 'list' }, rows);
            body.appendChild(list);
            renderCard(card, title, body);
            return;
        }

        // Not configured / still loading path.
        var notRunLabel = (dns && dns.note) ? dns.note
                       : (PCV2.i18n.dnsNotRun || 'DNS test not yet run.');
        body.appendChild(el('div', { class: 'pcv2__dns-provider-pill' }, [
            el('span', { class: 'pcv2__dns-provider-pill-label', text: 'Provider' }),
            el('span', { text: 'Pending probe…' })
        ]));
        body.appendChild(el('p', { class: 'pcv2__dns-note', text: notRunLabel }));
        renderCard(card, title, body);
    }

    function rebuildReportSkeleton(dashboard) {
        // Mirror the server-side skeleton in class-public-assets-v2.php
        // so a rescan (which clears reportRegion) still renders the
        // expected structure without needing a full page reload.
        var reportRegion = dashboard.querySelector('[data-pcv2-region="report"]');
        if (!reportRegion) return;

        var scoreHero = el('div', { class: 'pcv2__score-hero-host', 'data-pcv2-region': 'summary' });
        var grid = el('div', { class: 'pcv2__grid' });
        var findings = el('div', { class: 'pcv2__findings', 'data-pcv2-region': 'findings' });

        var cardKeys = ['overview', 'connection', 'anonymity', 'dns', 'browser', 'security'];
        cardKeys.forEach(function (key) {
            var card = el('article', { class: 'pcv2__card', 'data-pcv2-card': key });
            card.appendChild(el('header', { class: 'pcv2__card-header' }, [
                el('h2', { 'data-pcv2-region': 'card-title' })
            ]));
            card.appendChild(el('div', { class: 'pcv2__card-body', 'data-pcv2-region': 'card-body' }));
            grid.appendChild(card);
        });

        reportRegion.appendChild(scoreHero);
        reportRegion.appendChild(grid);
        reportRegion.appendChild(findings);
    }

    function renderReport(dashboard, report) {
        var intel = report.intel || {};
        var proxy = report.proxy || {};
        var conn = report.connection || {};
        var rep = report.reputation || {};

        // Stash the canonical report on the dashboard root so detail
        // helpers (tileDetailRows, etc.) can read it without us
        // threading it through every call site.
        try { dashboard.__lastReport = report; } catch (_e) { /* DOMProxy */ }

        // The static skeleton (score hero host, 6 cards, findings container)
        // is rendered once by the server-side shortcode. The reset path in
        // runScan() calls clear(reportRegion) which removes those nodes
        // along with their previous content. If they're gone (re-render
        // after a rescan), rebuild the skeleton before populating it.
        var reportRegion = dashboard.querySelector('[data-pcv2-region="report"]');
        if (!reportRegion) return;

        if (!dashboard.querySelector('[data-pcv2-region="summary"]')) {
            rebuildReportSkeleton(dashboard);
        }

        // Score hero (the big ring + 4 mini KPI rings).
        var summary = dashboard.querySelector('[data-pcv2-region="summary"]');
        clear(summary);
        // The canonical overall score lives in
        // report.privacy_report.overall — NOT report.privacy_score
        // (which is a deprecated stub that the backend leaves null).
        var privReport = report.privacy_report || {};
        var score = (typeof privReport.overall === 'number')
            ? privReport.overall
            : (report.privacy_score != null ? report.privacy_score : null);
        var grade = privReport.grade;
        summary.appendChild(renderScoreHero(report));

        // Cards.
        var cards = dashboard.querySelectorAll('.pcv2__card');
        cards.forEach(function (card) {
            var key = card.getAttribute('data-pcv2-card');
            if (key === 'overview') {
                // Overview: score + grade + confidence at-a-glance.
                var ovSummary = el('div', { class: 'pcv2__overview-summary' }, [
                    el('div', { class: 'pcv2__overview-summary-cell' }, [
                        el('span', { class: 'pcv2__overview-summary-cell-label', text: PCV2.i18n.scoreLabel || 'Privacy Score' }),
                        el('span', { class: 'pcv2__overview-summary-cell-value', text: score == null ? '—' : score + ' / 100' })
                    ]),
                    el('div', { class: 'pcv2__overview-summary-cell' }, [
                        el('span', { class: 'pcv2__overview-summary-cell-label', text: PCV2.i18n.gradeLabel || 'Grade' }),
                        el('span', { class: 'pcv2__overview-summary-cell-value pcv2__overview-summary-cell-value--grade', text: grade || '—' })
                    ]),
                    el('div', { class: 'pcv2__overview-summary-cell' }, [
                        el('span', { class: 'pcv2__overview-summary-cell-label', text: PCV2.i18n.confidenceLabel || 'Confidence' }),
                        el('span', { class: 'pcv2__overview-summary-cell-value', text: (report.privacy_report && report.privacy_report.confidence) || '—' })
                    ])
                ]);
                // Subscores bar chart (always present) — a real chart,
                // not a flat key-value list, so the user can see at a
                // glance which dimensions are pulling the score down.
                var subs = (report.privacy_report && report.privacy_report.subscores) || {};
                var cats = (report.privacy_report && report.privacy_report.categories) || {};
                var barItems = [];
                var subKeys = Object.keys(subs).slice(0, 6);
                if (subKeys.length === 0) {
                    // Fall back to the top 6 categories.
                    Object.keys(cats).slice(0, 6).forEach(function (k) {
                        subs[k] = { score: cats[k].percent || cats[k].score };
                        subKeys.push(k);
                    });
                }
                subKeys.forEach(function (k) {
                    var v = subs[k] || {};
                    var pct = typeof v === 'object' ? (v.score || v.percent) : v;
                    barItems.push({ label: prettySubLabel(k), value: pct, key: k });
                });
                var barChart = renderBarChart(barItems);
                renderCard(card, PCV2.i18n.overviewTitle || 'Overview', el('div', null, [ovSummary, barChart]));
            } else if (key === 'connection') {
                // Connection card — redesigned in Phase 23:
                //
                //   ┌─ IP badge (big, gradient, copy-to-clipboard) ─┐
                //   │  127.0.0.1           [📋 copy]                  │
                //   └────────────────────────────────────────────────┘
                //
                //   ┌─ signal panel ──────────────────────────────────┐
                //   │  [bars ▌▌▌▌▌]   country flag · city · region   │
                //   │  ISP · ASN · Timezone · Detected as: VPN?      │
                //   └────────────────────────────────────────────────┘
                //
                //   ┌─ fact tile grid (staggered animation) ──────────┐
                //   │  ┌─IPv4─┐ ┌─IPv6─┐ ┌─Country─┐ ┌─Timezone─┐  │
                //   │  └──────┘ └──────┘ └─────────┘ └──────────┘  │
                //   └────────────────────────────────────────────────┘
                var ipv4    = report.request_ip && report.request_ip.ipv4;
                var ipv6    = report.request_ip && report.request_ip.ipv6;
                var country = intel.country_name || intel.country || '';
                var cc      = intel.country || (intel.country_code || '').toUpperCase();
                var asn     = intel.asn;
                var isp     = intel.isp;
                var region  = intel.region;
                var city    = intel.city;
                var tz      = intel.timezone;
                var lat     = intel.latitude;
                var lon     = intel.longitude;
                var primaryIp = ipv4 || ipv6 || '';
                var body    = el('div', { class: 'pcv2__connection-body' });

                // ---- IP badge --------------------------------------
                if (primaryIp) {
                    var ipBadge = el('div', {
                        class: 'pcv2__connection-ip',
                        'data-pcv2-key': 'ip',
                        'data-pcv2-tone': primaryIp ? 'safe' : 'neutral'
                    });
                    var ipLabel = el('span', {
                        class: 'pcv2__connection-ip-label',
                        text: ipv4 && ipv6 ? 'IPv4 / IPv6' : (ipv4 ? 'IPv4' : 'IPv6')
                    });
                    var ipValue = el('span', {
                        class: 'pcv2__connection-ip-value mono',
                        text: ipv4 && ipv6
                            ? (ipv4 + '  ·  ' + ipv6)
                            : primaryIp
                    });
                    var copyBtn = el('button', {
                        type: 'button',
                        class: 'pcv2__connection-ip-copy',
                        'data-pcv2-action': 'copy-ip',
                        'data-pcv2-ip': primaryIp,
                        'aria-label': (PCV2.i18n.copyIpLabel || 'Copy IP address'),
                        title: (PCV2.i18n.copyIpLabel || 'Copy IP address')
                    }, '⧉');
                    ipBadge.appendChild(ipLabel);
                    ipBadge.appendChild(ipValue);
                    ipBadge.appendChild(copyBtn);
                    body.appendChild(ipBadge);
                }

                // ---- Signal panel ----------------------------------
                var signalPanel = el('div', { class: 'pcv2__connection-signal' });
                // Signal strength bar — 5 bars, animated fill from left.
                var bars = el('div', {
                    class: 'pcv2__signal-bars',
                    role: 'img',
                    'aria-label': (PCV2.i18n.signalAriaLabel || 'Signal strength')
                });
                var barCount = 5;
                for (var i = 0; i < barCount; i++) {
                    var bar = el('span', {
                        class: 'pcv2__signal-bar',
                        'data-pcv2-idx': String(i)
                    });
                    bar.style.setProperty('--pcv2-bar-delay', (i * 80) + 'ms');
                    bars.appendChild(bar);
                }
                signalPanel.appendChild(bars);

                var signalText = el('div', { class: 'pcv2__signal-text' });
                if (country) {
                    signalText.appendChild(el('span', {
                        class: 'pcv2__signal-flag',
                        'data-pcv2-cc': cc || '',
                        'aria-hidden': 'true',
                        text: countryCodeToFlag(cc)
                    }));
                }
                var locationParts = [city, region, country].filter(Boolean);
                if (locationParts.length > 0) {
                    signalText.appendChild(el('span', {
                        class: 'pcv2__signal-location',
                        text: locationParts.join(' · ')
                    }));
                } else {
                    // No geo intel — show what's still useful instead of
                    // a dead-end "unavailable" placeholder. On hosts that
                    // block outbound IP-intel APIs (e.g. InfinityFree, some
                    // corporate firewalls), the IP is still known but
                    // city/country/ASN aren't. Show the proxy verdict
                    // (which is computed locally without external calls)
                    // plus an explicit reason so it doesn't read as
                    // "broken" — just "limited intel".
                    var proxyLabel = (proxy && proxy.label) ? proxy.label : '';
                    var proxyCat   = (proxy && proxy.category) ? proxy.category : '';
                    var geoFallback = primaryIp
                        ? ( proxyLabel && /^(vpn|proxy|tor|hosting)/i.test(proxyCat)
                            ? (proxyLabel + ' — geo lookup unavailable on this host')
                            : (proxyLabel && proxyLabel !== 'No signal'
                                ? proxyLabel + ' — geo lookup unavailable on this host'
                                : (PCV2.i18n.geoPending || 'Geo lookup unavailable')) )
                        : (PCV2.i18n.signalPending || 'Awaiting connection…');
                    signalText.appendChild(el('span', {
                        class: 'pcv2__row-missing',
                        text: geoFallback
                    }));
                }
                if (isp) {
                    signalText.appendChild(el('span', {
                        class: 'pcv2__signal-isp',
                        text: isp + (asn ? ' · ' + asn : '')
                    }));
                }
                signalPanel.appendChild(signalText);

                // Optional: tiny inline "globe" with a pulsing pin when
                // we have lat/lon — pure decorative accent.
                if (typeof lat === 'number' && typeof lon === 'number') {
                    var globe = el('div', { class: 'pcv2__signal-globe', 'aria-hidden': 'true' });
                    var pin = el('span', { class: 'pcv2__signal-pin' });
                    globe.appendChild(pin);
                    signalPanel.appendChild(globe);
                }
                body.appendChild(signalPanel);

                // ---- Connection type (Network Information API) ------
                // Phase 26: read navigator.connection if the browser
                // exposes it. The API gives us type (wifi/cellular/
                // ethernet/mixed/unknown), effectiveType (4g/3g/2g/
                // slow-2g), downlink (Mbps), and rtt (ms). Operator
                // and vendor are not exposed by any standard browser
                // API — for satellite connections (Starlink, etc.)
                // we fall back to ASN-based heuristics: ASNs in the
                // 14593 / 59717 / 54825 range are commonly used by
                // satellite operators, and ASNs around 35804 / 35805
                // are KNOWN-SK / STCN which are typically fibre or
                // residential broadband. The point is to surface
                // *something* useful — the user can always click the
                // tile to see the full evidence trail.
                var connType = '';
                var connEffective = '';
                var connDownlink = null;
                var connRtt = null;
                try {
                    var nci = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
                    if (nci) {
                        connType = nci.type || '';
                        connEffective = nci.effectiveType || '';
                        connDownlink = typeof nci.downlink === 'number' ? nci.downlink : null;
                        connRtt = typeof nci.rtt === 'number' ? nci.rtt : null;
                    }
                } catch (_e) { /* some browsers throw on read */ }
                // Heuristic: infer "satellite" from ASN when the API
                // doesn't report it directly.
                if (!/satellite/i.test(connType)) {
                    var asnStr = String(asn || '');
                    var asnNum = parseInt(asnStr.replace(/^AS/i, ''), 10);
                    var satelliteAsns = {
                        14593: 'Starlink (SpaceX)',
                        59717: 'Starlink (SpaceX)',
                        54825: 'Starlink (SpaceX)',
                        27277: 'Starlink (legacy)',
                        1239:  'Sprint (legacy satellite)',
                        7493:  'ViaSat',
                        7156:  'ViaSat',
                        16824: 'SES Networks'
                    };
                    if (satelliteAsns[asnNum]) {
                        connType = 'satellite';
                    }
                }
                // Phase 31c: ASN-based classification as a final fallback
                // when both the browser API and the RTT/downlink
                // heuristic leave the type ambiguous. Static lookup of
                // well-known operator ASNs across residential broadband,
                // cellular, hosting, and education categories. The
                // lookup is intentionally conservative: only flag an ASN
                // when its operator is unambiguously one class.
                var asnClass = classifyAsn(asn);
                var connTypeLabel = connType
                    ? ({
                        wifi:     'Wi-Fi',
                        cellular: 'Cellular',
                        ethernet: 'Ethernet',
                        satellite:'Satellite',
                        mixed:    'Mixed',
                        wimax:    'WiMAX',
                        vpn:      'VPN tunnel',
                        bluetooth:'Bluetooth',
                        none:     'Offline'
                    }[connType.toLowerCase()] || (connType.charAt(0).toUpperCase() + connType.slice(1)))
                    : '';
                // Phase 31d: do NOT fall back to effectiveType on its own.
                // Chromium reports effectiveType=4g on every desktop browser
                // whether the link is Wi-Fi, Ethernet, or cellular — it's a
                // cellular-tier hint, not a connection-class hint. If `type`
                // is empty, prefer the RTT/downlink inference (set just
                // below) over a misleading "4G" label on a wired/Wi-Fi link.
                // We only honour effectiveType as the connection label when
                // the browser also reported a meaningful `type` of its own.
                if (connEffective && !connTypeLabel && connType) {
                    connTypeLabel = connEffective.toUpperCase();
                }
                // Phase 31b: when the browser reports `type === 'unknown'`
                // and `effectiveType` is empty (common on macOS, Linux, and
                // Chromium without the NetworkService flag — i.e. almost
                // every WiFi-only network), don't leave the tile reading
                // "Unknown". Infer from the network evidence we already
                // have: high downlink + low RTT → broadband (Wi-Fi or
                // Ethernet); low downlink + high RTT → cellular; satellite
                // ASNs override everything. This is heuristic but it's
                // strictly better than "Unknown" when the API gave us
                // nothing useful.
                if ((!connTypeLabel || /^unknown$/i.test(connTypeLabel)) && (!connType || /unknown/i.test(connType)) && !connEffective) {
                    if (typeof connDownlink === 'number' || typeof connRtt === 'number') {
                        if (connRtt != null && connRtt >= 100) {
                            connTypeLabel = 'Cellular (inferred)';
                        } else if (connDownlink != null && connDownlink >= 5) {
                            connTypeLabel = 'Wi-Fi / Ethernet (inferred)';
                        } else if (connDownlink != null && connDownlink < 1) {
                            connTypeLabel = 'Cellular (inferred)';
                        } else {
                            connTypeLabel = 'Wi-Fi / Ethernet (inferred)';
                        }
                    } else {
                        // No downlink/RTT data either — leave the label
                        // empty; the ASN classifier below will fill in
                        // a confident answer when the operator ASN is
                        // known.
                    }
                }
                // Phase 31c: ASN-based override. After the RTT/downlink
                // heuristic, if the label is still empty or just says
                // "(inferred)" without operator context, look up the
                // ASN. Known-operator ASNs are confident enough to
                // upgrade from "(inferred)" to the operator name.
                if ((!connTypeLabel || /\(inferred\)$/i.test(connTypeLabel)) && asnClass && asnClass.label) {
                    connTypeLabel = asnClass.label;
                } else if (!connTypeLabel && asnClass && asnClass.className) {
                    connTypeLabel = asnClass.className + ' (inferred)';
                }

                // ---- Fact tile grid -------------------------------
                var factItems = [
                    { label: 'IPv4',       value: ipv4,    mono: true, tone: ipv4 ? 'safe' : 'neutral', icon: '4' },
                    { label: 'IPv6',       value: ipv6,    mono: true, tone: ipv6 ? 'safe' : 'neutral', icon: '6' },
                    { label: 'Country',    value: country, mono: false, tone: country ? 'safe' : 'neutral', icon: '🌐' },
                    { label: 'Region',     value: region,  mono: false, tone: region ? 'safe' : 'neutral', icon: '◎' },
                    { label: 'City',       value: city,    mono: false, tone: city ? 'safe' : 'neutral', icon: '◉' },
                    { label: 'Timezone',   value: tz,      mono: true,  tone: tz ? 'safe' : 'neutral', icon: '⧖' },
                    { label: 'ISP',        value: isp,     mono: false, tone: isp ? 'safe' : 'neutral', icon: '⚙' },
                    { label: 'ASN',        value: asn,     mono: true,  tone: asn ? 'safe' : 'neutral', icon: 'ASN' },
                    { label: 'Connection', value: connTypeLabel || null,
                      mono: false,
                      tone: connTypeLabel ? 'safe' : 'neutral',
                      icon: connType === 'wifi' ? '📶'
                          : connType === 'cellular' ? '📱'
                          : connType === 'ethernet' ? '🔌'
                          : connType === 'satellite' ? '🛰'
                          : connType === 'vpn' ? '🛡'
                          : connType === 'bluetooth' ? '📲'
                          : '⚡',
                      // Pass the API snapshot through to the detail
                      // helper via a custom property on the value.
                      _detail: {
                          type: connType, effectiveType: connEffective,
                          downlink: connDownlink, rtt: connRtt,
                          asn: asn, isp: isp
                      }
                    }
                ];
                var factGrid = el('div', { class: 'pcv2__connection-facts' });
                factItems.forEach(function (it, idx) {
                    // Phase 25: tiles are now native <details> with
                    // click-to-expand detail panels. Use the shared
                    // renderFactTile() helper so all four cards share
                    // the same expand behaviour and animation timing.
                    factGrid.appendChild(renderFactTile({
                        key:   it.label.toLowerCase(),
                        label: it.label,
                        value: it.value,
                        mono:  !!it.mono,
                        tone:  it.tone,
                        icon:  it.icon,
                        delay: idx * 60
                    }));
                });
                body.appendChild(factGrid);
                attachTileExpand(factGrid);

                // Phase 31: when the visitor switches networks (4G → WiFi
                // → Ethernet), Chromium fires `navigator.connection`'s
                // `change` event. Without this listener the tile keeps
                // showing the stale connection label until the next full
                // rescan. We patch the "Connection" tile in place rather
                // than re-rendering the whole card so the rest of the
                // report stays steady while the live value updates.
                (function () {
                    try {
                        var nci = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
                        if (!nci || typeof nci.addEventListener !== 'function') return;
                        nci.addEventListener('change', function () {
                            var live = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
                            if (!live) return;
                            var liveType      = live.type || '';
                            var liveEffective = live.effectiveType || '';
                            var liveDownlink  = typeof live.downlink === 'number' ? live.downlink : null;
                            var liveRtt       = typeof live.rtt === 'number' ? live.rtt : null;
                            var liveLabel = liveType
                                ? ({
                                    wifi: 'Wi-Fi', cellular: 'Cellular', ethernet: 'Ethernet',
                                    satellite: 'Satellite', mixed: 'Mixed', wimax: 'WiMAX',
                                    vpn: 'VPN tunnel', bluetooth: 'Bluetooth', none: 'Offline'
                                }[liveType.toLowerCase()] || (liveType.charAt(0).toUpperCase() + liveType.slice(1)))
                                : (liveEffective ? liveEffective.toUpperCase() : '');
                            // Phase 31b: same inference for the live update.
                            if ((!liveLabel || /^unknown$/i.test(liveLabel)) && (!liveType || /unknown/i.test(liveType)) && !liveEffective) {
                                if (liveRtt != null && liveRtt >= 100) {
                                    liveLabel = 'Cellular (inferred)';
                                } else if (liveDownlink != null && liveDownlink >= 5) {
                                    liveLabel = 'Wi-Fi / Ethernet (inferred)';
                                } else if (liveDownlink != null && liveDownlink < 1) {
                                    liveLabel = 'Cellular (inferred)';
                                } else {
                                    liveLabel = 'Wi-Fi / Ethernet (inferred)';
                                }
                            }
                            // Phase 31c: ASN-based override on top of the
                            // RTT/downlink inference. If the live API +
                            // heuristic are still ambiguous, trust the
                            // operator's known ASN class.
                            if (!liveLabel || /\(inferred\)$/i.test(liveLabel)) {
                                var asnHint = classifyAsn(asn);
                                if (asnHint && asnHint.label) {
                                    liveLabel = asnHint.label;
                                }
                            }
                            var tile = factGrid.querySelector('[data-pcv2-key="connection"]');
                            if (!tile) return;
                            var valueEl = tile.querySelector('.pcv2__connection-tile-value');
                            if (valueEl) {
                                valueEl.textContent = liveLabel || (PCV2.i18n.noData || '—');
                            }
                            // Update the detail panel content too so the
                            // expanded tile reflects the live API values.
                            var detailEl = tile.querySelector('.pcv2__connection-tile-detail');
                            if (detailEl) {
                                detailEl.innerHTML = '';
                                var dl = live.downlink;
                                var rt = live.rtt;
                                if (liveType)      detailEl.appendChild(el('div', {}, [el('strong', { text: 'Type' }), el('span', { text: liveType })]));
                                if (liveEffective) detailEl.appendChild(el('div', {}, [el('strong', { text: 'Effective' }), el('span', { text: liveEffective })]));
                                if (dl != null)     detailEl.appendChild(el('div', {}, [el('strong', { text: 'Downlink' }), el('span', { text: dl + ' Mbps' })]));
                                if (rt != null)     detailEl.appendChild(el('div', {}, [el('strong', { text: 'RTT' }), el('span', { text: rt + ' ms' })]));
                            }
                        });
                    } catch (_e) { /* listener unsupported */ }
                })();

                renderCard(card, PCV2.i18n.connectionTitle || 'Connection', body);
            } else if (key === 'anonymity') {
                // Anonymity card — redesigned in Phase 24:
                //
                //   ┌─ verdict pill (large, tone glow, animated halo) ─┐
                //   │  Detection                                       │
                //   │  No signal · VPN · Tor · Proxy                   │
                //   └──────────────────────────────────────────────────┘
                //
                //   ┌─ confidence meter (horizontal fill bar) ─────────┐
                //   │  high ████████░░ low                            │
                //   └──────────────────────────────────────────────────┘
                //
                //   ┌─ fact tiles ─────────────────────────────────────┐
                //   │  Type · Confidence · ASN · Country · ISP        │
                //   └──────────────────────────────────────────────────┘
                var proxyTone = proxy.label === 'No signal' ? 'safe'
                              : proxy.label && /tor/i.test(proxy.label) ? 'danger'
                              : proxy.label && /proxy/i.test(proxy.label) ? 'warning'
                              : proxy.label && /vpn/i.test(proxy.label) ? 'warning'
                              : proxy.label && /hosting/i.test(proxy.label) ? 'warning'
                              : 'neutral';
                // Phase 51: on hosts that block outbound IP-intel APIs,
                // AnonymityScorer can't correlate and the consistency
                // verdict is "Unknown". But the proxy verdict (computed
                // locally) is still trustworthy — don't replace a useful
                // "VPN (Cloudflare WARP)" label with a generic "Unknown".
                // Only fall back to "Unknown" when there's no proxy info
                // at all (label empty AND category empty).
                var proxyLabel = proxy.label
                    || (proxy.category && proxy.category !== 'none' ? proxy.category : '')
                    || (PCV2.i18n.noConfidence || 'Unknown');
                var conf = (proxy.confidence || '').toLowerCase();
                var confPct = conf === 'high' ? 88
                            : conf === 'medium' ? 60
                            : conf === 'low' ? 30
                            : 0;
                var body = el('div', { class: 'pcv2__anonymity-body' });

                // ---- Verdict pill ------------------------------------
                var verdict = el('div', {
                    class: 'pcv2__anonymity-verdict',
                    'data-pcv2-tone': proxyTone
                });
                var verdictLabel = el('div', {
                    class: 'pcv2__anonymity-verdict-label',
                    text: PCV2.i18n.detectionLabel || 'Detection'
                });
                var verdictName = el('div', {
                    class: 'pcv2__anonymity-verdict-name',
                    text: proxyLabel
                });
                verdict.appendChild(verdictLabel);
                verdict.appendChild(verdictName);
                body.appendChild(verdict);

                // ---- Confidence meter --------------------------------
                if (proxy.confidence) {
                    var meter = el('div', {
                        class: 'pcv2__anonymity-meter',
                        role: 'progressbar',
                        'aria-valuemin': '0',
                        'aria-valuemax': '100',
                        'aria-valuenow': String(confPct),
                        'aria-label': (PCV2.i18n.confidenceLabel || 'Confidence') + ': ' + proxy.confidence
                    });
                    var meterTrack = el('div', { class: 'pcv2__anonymity-meter-track' });
                    var meterFill = el('span', {
                        class: 'pcv2__anonymity-meter-fill',
                        'data-pcv2-tone': proxyTone
                    });
                    meterFill.style.setProperty('--pcv2-meter-target', confPct + '%');
                    meterTrack.appendChild(meterFill);
                    var meterLabel = el('div', { class: 'pcv2__anonymity-meter-label' });
                    meterLabel.appendChild(el('span', {
                        text: (PCV2.i18n.confidenceLabel || 'Confidence')
                    }));
                    meterLabel.appendChild(el('span', {
                        class: 'pcv2__anonymity-meter-value',
                        text: proxy.confidence
                    }));
                    meter.appendChild(meterTrack);
                    meter.appendChild(meterLabel);
                    body.appendChild(meter);
                    // Animate fill on next frame.
                    if (typeof requestAnimationFrame === 'function') {
                        requestAnimationFrame(function () {
                            meterFill.style.width = confPct + '%';
                        });
                    } else {
                        meterFill.style.width = confPct + '%';
                    }
                }

                // ---- Fact tiles --------------------------------------
                var factItems = [
                    { label: 'Type',        value: proxy.type,  tone: proxyTone, icon: '◐' },
                    { label: 'Confidence',  value: proxy.confidence, tone: proxyTone, icon: '◈' },
                    { label: 'ASN',         value: intel.asn,  mono: true, tone: 'safe', icon: 'ASN' },
                    { label: 'Country',     value: intel.country_name || intel.country, tone: 'safe', icon: '🌐' },
                    { label: 'ISP',         value: intel.isp,  tone: 'safe', icon: '⚙' },
                    { label: 'IP',          value: (report.request_ip && report.request_ip.ipv4) || null, mono: true, tone: 'safe', icon: '4' }
                ];
                var factGrid = el('div', { class: 'pcv2__connection-facts' });
                factItems.forEach(function (it, idx) {
                    factGrid.appendChild(renderFactTile({
                        key:   it.label.toLowerCase(),
                        label: it.label,
                        value: it.value,
                        mono:  !!it.mono,
                        tone:  it.tone,
                        icon:  it.icon,
                        delay: idx * 60
                    }));
                });
                body.appendChild(factGrid);
                attachTileExpand(factGrid);

                renderCard(card, PCV2.i18n.anonymityTitle || 'Anonymity', body);
            } else if (key === 'dns') {
                // DNS: render the resolver detail from the parallel probe
                // result, or show a "pending" placeholder if the probe
                // hasn't landed yet.
                var dns = report.dns_test || rep.dns || {};
                renderDnsCard(card, dns);
            } else if (key === 'browser') {
                // Browser card — redesigned in Phase 24:
                //
                //   ┌─ UA badge (big, mono, copy-to-clipboard) ────────┐
                //   │  Mozilla/5.0 ...                    [📋 copy]     │
                //   └───────────────────────────────────────────────────┘
                //
                //   ┌─ feature chips (canvas / webgl / fonts / plugins) ┐
                //   └───────────────────────────────────────────────────┘
                //
                //   ┌─ fact tiles ───────────────────────────────────────┐
                //   │  Browser · Engine · OS · Screen · Languages · ...  │
                //   └───────────────────────────────────────────────────┘
                var fp = report.fingerprint || {};
                var ua = report.user_agent || {};
                var uaStr = uaDisplayValue(ua);
                var body = el('div', { class: 'pcv2__browser-body' });

                // ---- UA badge ----------------------------------------
                if (uaStr) {
                    var uaBadge = el('div', {
                        class: 'pcv2__browser-ua',
                        'data-pcv2-tone': 'safe'
                    });
                    var uaLabel = el('span', {
                        class: 'pcv2__browser-ua-label',
                        text: PCV2.i18n.userAgentLabel || 'User Agent'
                    });
                    var uaValue = el('span', {
                        class: 'pcv2__browser-ua-value mono',
                        text: uaStr
                    });
                    var uaCopy = el('button', {
                        type: 'button',
                        class: 'pcv2__connection-ip-copy',
                        'data-pcv2-action': 'copy-ua',
                        'data-pcv2-ua': uaStr,
                        'aria-label': (PCV2.i18n.copyUaLabel || 'Copy user agent'),
                        title: (PCV2.i18n.copyUaLabel || 'Copy user agent')
                    }, '⧉');
                    uaBadge.appendChild(uaLabel);
                    uaBadge.appendChild(uaValue);
                    uaBadge.appendChild(uaCopy);
                    body.appendChild(uaBadge);
                }

                // ---- Feature chips -----------------------------------
                var features = fp.features || {};
                var featureItems = [
                    { label: 'Canvas',  on: !!features.canvas },
                    { label: 'WebGL',   on: !!features.webgl },
                    { label: 'Audio',   on: !!features.audio },
                    { label: 'Fonts',   on: !!features.fonts },
                    { label: 'Plugins', on: !!features.plugins },
                    { label: 'Battery', on: !!features.battery }
                ];
                var chipList = el('div', { class: 'pcv2__browser-chips' });
                featureItems.forEach(function (f, idx) {
                    var chip = el('span', {
                        class: 'pcv2__browser-chip',
                        'data-pcv2-on': f.on ? '1' : '0',
                        'data-pcv2-key': f.label.toLowerCase()
                    });
                    chip.style.setProperty('--pcv2-chip-delay', (idx * 50) + 'ms');
                    chip.appendChild(el('span', {
                        class: 'pcv2__browser-chip-dot',
                        'aria-hidden': 'true',
                        text: f.on ? '●' : '○'
                    }));
                    chip.appendChild(el('span', {
                        class: 'pcv2__browser-chip-label',
                        text: f.label
                    }));
                    chipList.appendChild(chip);
                });
                body.appendChild(chipList);

                // ---- Fact tiles --------------------------------------
                var uaParts = ua || {};
                var browserRows = [
                    { label: 'Browser', value: uaBrowserName(uaParts), tone: 'safe', icon: '◉' },
                    { label: 'Engine',  value: uaParts.engine, tone: 'safe', icon: '⚙' },
                    { label: 'OS',      value: uaParts.os, tone: 'safe', icon: '⊞' },
                    { label: 'Device',  value: uaParts.device, tone: 'safe', icon: '▣' },
                    { label: 'Languages', value: (navigator.languages || []).join(', ') || null, tone: 'safe', icon: '🗣' },
                    { label: 'Timezone',  value: (Intl.DateTimeFormat().resolvedOptions().timeZone) || null, mono: true, tone: 'safe', icon: '⧖' },
                    { label: 'Screen',    value: screen.width + ' × ' + screen.height, mono: true, tone: 'safe', icon: '▭' },
                    { label: 'Entropy',   value: fp.entropy_bits ? fp.entropy_bits + ' bits' : null, mono: true, tone: fp.entropy_bits >= 12 ? 'safe' : (fp.entropy_bits >= 8 ? 'warning' : 'danger'), icon: 'Σ' }
                ];
                var factGrid = el('div', { class: 'pcv2__connection-facts' });
                browserRows.forEach(function (it, idx) {
                    factGrid.appendChild(renderFactTile({
                        key:   it.label.toLowerCase(),
                        label: it.label,
                        value: it.value,
                        mono:  !!it.mono,
                        tone:  it.tone,
                        icon:  it.icon,
                        delay: idx * 60
                    }));
                });
                body.appendChild(factGrid);
                attachTileExpand(factGrid);

                renderCard(card, PCV2.i18n.browserTitle || 'Browser Privacy', body);
            } else if (key === 'security') {
                // Security card — redesigned in Phase 24:
                //
                //   ┌─ verdict pill (large, tone glow) ──────────────┐
                //   │  Security Posture                               │
                //   │  STRONG · ADEQUATE · AT RISK                    │
                //   └─────────────────────────────────────────────────┘
                //
                //   ┌─ threat meters (TLS + Browser version) ─────────┐
                //   │  TLS 1.3  ███████░░  Good                       │
                //   │  Chrome 110+ █████░░░░  Outdated                │
                //   └─────────────────────────────────────────────────┘
                //
                //   ┌─ fact tiles ─────────────────────────────────────┐
                //   │  TLS · TLS Status · Browser · Outdated · ...    │
                //   └─────────────────────────────────────────────────┘
                var sp = report.security_posture || {};
                var tlsVer = sp.tls && sp.tls.version;
                var tlsStatus = sp.tls && sp.tls.status;
                var browserVer = sp.browser && (
                    (sp.browser.browser || '') +
                    (sp.browser.version ? ' ' + sp.browser.version : '')
                ).trim();
                var outdated = sp.browser && sp.browser.outdated;
                var verdictTone = (tlsStatus === 'good' && !outdated) ? 'safe'
                                : (tlsStatus === 'bad' || outdated) ? 'danger'
                                : 'warning';
                var verdictLabel = (tlsStatus === 'good' && !outdated) ? (PCV2.i18n.securityStrong || 'Strong')
                                 : (tlsStatus === 'bad' || outdated) ? (PCV2.i18n.securityAtRisk || 'At Risk')
                                 : (PCV2.i18n.securityAdequate || 'Adequate');
                var body = el('div', { class: 'pcv2__security-body' });

                // ---- Verdict pill ------------------------------------
                var verdict = el('div', {
                    class: 'pcv2__anonymity-verdict',
                    'data-pcv2-tone': verdictTone
                });
                verdict.appendChild(el('div', {
                    class: 'pcv2__anonymity-verdict-label',
                    text: PCV2.i18n.securityPostureLabel || 'Security Posture'
                }));
                verdict.appendChild(el('div', {
                    class: 'pcv2__anonymity-verdict-name',
                    text: verdictLabel
                }));
                body.appendChild(verdict);

                // ---- Threat meters (TLS + Browser) -------------------
                var tlsPct = tlsStatus === 'good' ? 95
                          : tlsStatus === 'bad'  ? 20
                          : 55;
                var browserPct = outdated ? 35 : 90;
                var tlsTone = tlsStatus === 'good' ? 'safe'
                            : tlsStatus === 'bad'  ? 'danger'
                            : 'warning';
                var browserTone = outdated ? 'warning' : 'safe';
                var meters = el('div', { class: 'pcv2__security-meters' });
                function buildMeter(label, value, pct, tone) {
                    var meter = el('div', {
                        class: 'pcv2__security-meter',
                        role: 'progressbar',
                        'aria-valuemin': '0',
                        'aria-valuemax': '100',
                        'aria-valuenow': String(pct),
                        'aria-label': label + ': ' + pct + ' of 100'
                    });
                    var meterHead = el('div', { class: 'pcv2__security-meter-head' });
                    meterHead.appendChild(el('span', {
                        class: 'pcv2__security-meter-label',
                        text: label
                    }));
                    meterHead.appendChild(el('span', {
                        class: 'pcv2__security-meter-value',
                        'data-pcv2-tone': tone,
                        text: value || '—'
                    }));
                    meter.appendChild(meterHead);
                    var track = el('div', { class: 'pcv2__anonymity-meter-track' });
                    var fill = el('span', {
                        class: 'pcv2__anonymity-meter-fill',
                        'data-pcv2-tone': tone
                    });
                    fill.style.setProperty('--pcv2-meter-target', pct + '%');
                    track.appendChild(fill);
                    meter.appendChild(track);
                    if (typeof requestAnimationFrame === 'function') {
                        requestAnimationFrame(function () { fill.style.width = pct + '%'; });
                    } else {
                        fill.style.width = pct + '%';
                    }
                    return meter;
                }
                if (tlsVer) {
                    meters.appendChild(buildMeter('TLS ' + tlsVer, tlsStatus, tlsPct, tlsTone));
                }
                if (sp.browser) {
                    var browserName = (sp.browser.browser || 'Browser') + (outdated ? ' — outdated' : ' — current');
                    meters.appendChild(buildMeter(browserName, outdated ? 'Outdated' : 'Current', browserPct, browserTone));
                }
                body.appendChild(meters);

                // ---- Fact tiles --------------------------------------
                var factItems = [
                    { label: 'TLS',         value: tlsVer, mono: true, tone: tlsTone, icon: '🔒' },
                    { label: 'TLS Status',  value: tlsStatus, tone: tlsTone, icon: tlsStatus === 'good' ? '✓' : (tlsStatus === 'bad' ? '✕' : '!') },
                    { label: 'Browser',     value: browserVer || null, mono: true, tone: browserTone, icon: '◉' },
                    { label: 'Outdated',    value: outdated ? (PCV2.i18n.yes || 'Yes') : (PCV2.i18n.no || 'No'), tone: outdated ? 'warning' : 'safe', icon: outdated ? '!' : '✓' }
                ];
                var factGrid = el('div', { class: 'pcv2__connection-facts' });
                factItems.forEach(function (it, idx) {
                    factGrid.appendChild(renderFactTile({
                        key:   it.label.toLowerCase(),
                        label: it.label,
                        value: it.value,
                        mono:  !!it.mono,
                        tone:  it.tone,
                        icon:  it.icon,
                        delay: idx * 60
                    }));
                });
                body.appendChild(factGrid);
                attachTileExpand(factGrid);

                renderCard(card, PCV2.i18n.securityTitle || 'Security Findings', body);
            }
        });

        // Findings list (expandable rows with scoring rubric + evidence).
        var findings = dashboard.querySelector('[data-pcv2-region="findings"]');
        clear(findings);
        var cats = (report.privacy_report && report.privacy_report.categories) || {};
        var list = el('div', { class: 'pcv2__findings' });
        var findingsHeader = el('div', { class: 'pcv2__findings-header' }, [
            el('h3', { text: PCV2.i18n.findingsTitle || 'Privacy Findings' }),
            el('span', { class: 'pcv2__findings-hint', text: PCV2.i18n.findingsHint || 'Click any row for scoring details and evidence.' })
        ]);
        list.appendChild(findingsHeader);
        var findingIcons = { safe: '✓', warning: '!', danger: '✕', info: 'ⓘ', neutral: '·' };

        Object.keys(cats).forEach(function (k) {
            var c = cats[k];
            if (!c) return;
            var scoreVal = Math.round(c.score || c.percent || 0);
            var sev = severityFromScore(scoreVal);

            // Native <details> wrapper for a11y + keyboard support out of the box.
            var detailsAttrs = {
                class: 'pcv2__finding',
                'data-pcv2-severity': sev,
                'data-pcv2-key': k,
                'data-pcv2-score': String(scoreVal)
            };
            var details = el('details', detailsAttrs);

            // Summary row (always visible, clickable).
            var summary = el('summary', { class: 'pcv2__finding-summary' });
            summary.appendChild(el('div', {
                class: 'pcv2__finding-icon',
                'aria-hidden': 'true',
                text: findingIcons[sev] || '·'
            }));
            summary.appendChild(el('div', { class: 'pcv2__finding-head' }, [
                el('p', { class: 'pcv2__finding-title', text: prettySubLabel(k) + ' — ' + scoreVal + ' / 100' }),
                el('p', { class: 'pcv2__finding-body',  text: c.message || (PCV2.i18n.noDetails || 'No additional details available.') })
            ]));
            summary.appendChild(el('div', { class: 'pcv2__finding-score-wrap' }, [
                el('span', { class: 'pcv2__finding-score', text: scoreVal + '%' }),
                el('span', { class: 'pcv2__finding-chevron', 'aria-hidden': 'true', text: '▾' })
            ]));
            details.appendChild(summary);

            // Expandable body: scoring rubric + evidence + recommendation.
            var body = el('div', { class: 'pcv2__finding-details' });

            // 1. Scoring rubric — which band was hit, plus all bands for context.
            var rubricBlock = el('div', { class: 'pcv2__finding-block' });
            rubricBlock.appendChild(el('h4', {
                class: 'pcv2__finding-block-title',
                text: PCV2.i18n.rubricTitle || 'How this score was calculated'
            }));
            var criteria = Array.isArray(c.criteria) ? c.criteria : [];
            var hit = criteria.find(function (b) { return b.score === scoreVal; });
            if (hit) {
                var verdict = el('div', { class: 'pcv2__finding-verdict' }, [
                    el('span', {
                        class: 'pcv2__status',
                        'data-pcv2-status': sev === 'safe' ? 'safe' : sev === 'danger' ? 'danger' : 'warning'
                    }, hit.label),
                    el('span', { class: 'pcv2__finding-verdict-text', text: hit.condition })
                ]);
                rubricBlock.appendChild(verdict);
            } else {
                rubricBlock.appendChild(el('p', {
                    class: 'pcv2__finding-verdict-text',
                    text: PCV2.i18n.noRubric || 'No scoring rubric available for this category.'
                }));
            }
            if (criteria.length > 0) {
                var rubric = el('ul', { class: 'pcv2__finding-rubric' });
                criteria.forEach(function (band) {
                    var li = el('li', {
                        class: 'pcv2__finding-band' + (band === hit ? ' pcv2__finding-band--hit' : ''),
                        'data-pcv2-tone': band.label.toLowerCase() === 'good' ? 'safe'
                                        : band.label.toLowerCase() === 'bad' ? 'danger'
                                        : 'warning'
                    });
                    li.appendChild(el('span', { class: 'pcv2__finding-band-score', text: band.score }));
                    li.appendChild(el('span', { class: 'pcv2__finding-band-condition', text: band.condition }));
                    rubric.appendChild(li);
                });
                rubricBlock.appendChild(rubric);
            }
            body.appendChild(rubricBlock);

            // 2. Evidence — the raw signal values that contributed to the score.
            var details_ = c.details && typeof c.details === 'object' ? c.details : {};
            var detailKeys = Object.keys(details_);
            if (detailKeys.length > 0) {
                var evBlock = el('div', { class: 'pcv2__finding-block' });
                evBlock.appendChild(el('h4', {
                    class: 'pcv2__finding-block-title',
                    text: PCV2.i18n.evidenceTitle || 'Evidence'
                }));
                var dl = el('dl', { class: 'pcv2__finding-evidence' });
                detailKeys.forEach(function (dk) {
                    var raw = details_[dk];
                    var display = raw;
                    if (raw && typeof raw === 'object') {
                        display = JSON.stringify(raw);
                    } else if (raw === '' || raw == null) {
                        return; // skip empty
                    }
                    dl.appendChild(el('dt', { text: prettySubLabel(dk) }));
                    dl.appendChild(el('dd', {
                        class: 'mono',
                        text: String(display)
                    }));
                });
                if (dl.children.length > 0) {
                    evBlock.appendChild(dl);
                    body.appendChild(evBlock);
                }
            }

            // 3. Status source — was the score measured or estimated?
            if (c.status_source && c.status_source !== 'measured') {
                var srcBlock = el('div', { class: 'pcv2__finding-block' }, [
                    el('h4', {
                        class: 'pcv2__finding-block-title',
                        text: PCV2.i18n.sourceTitle || 'Data source'
                    }),
                    el('p', {
                        class: 'pcv2__finding-source-note',
                        text: c.status_source === 'unknown'
                            ? (PCV2.i18n.sourceUnknown || 'This category was scored from limited data — the underlying provider did not respond.')
                            : (PCV2.i18n.sourceEstimated || 'This category was estimated; no direct measurement was available.')
                    })
                ]);
                body.appendChild(srcBlock);
            }

            // 4. Recommendation — what to do about this finding.
            var rec = pickRecommendation(c, k);
            if (rec) {
                var recBlock = el('div', { class: 'pcv2__finding-block pcv2__finding-block--rec' }, [
                    el('h4', {
                        class: 'pcv2__finding-block-title',
                        text: PCV2.i18n.recTitle || 'What you can do'
                    }),
                    el('p', { class: 'pcv2__finding-rec', text: rec })
                ]);
                body.appendChild(recBlock);
            }

            details.appendChild(body);
            list.appendChild(details);
        });
        findings.appendChild(list);

        // ---- A+ suggestion box (Phase 27) -------------------------
        // A prioritized list of actions the user can take to improve
        // their privacy score. Sorted by current score (worst first)
        // so the biggest wins are at the top. Each item shows the
        // category, current score, and a concrete recommendation.
        var suggestionsHost = findings.parentNode.querySelector(':scope > .pcv2__suggestions');
        if (!suggestionsHost) {
            suggestionsHost = el('section', {
                class: 'pcv2__suggestions',
                'aria-labelledby': 'pcv2-suggestions-heading'
            });
            findings.parentNode.insertBefore(suggestionsHost, findings.nextSibling);
        }
        clear(suggestionsHost);
        suggestionsHost.appendChild(renderSuggestionsBox(cats, privReport));

        // Post-scan share/export bar — reuse the static host if the
        // server-rendered skeleton has one (Phase 19 inline layout),
        // otherwise create one next to the findings region.
        var actionsHost = findings.parentNode.querySelector(':scope > .pcv2__actions-host');
        if (!actionsHost) {
            actionsHost = el('div', { class: 'pcv2__actions-host' });
            findings.parentNode.insertBefore(actionsHost, suggestionsHost.nextSibling);
        }
        renderPostScanActions(report, actionsHost);
    }

    /**
     * Render the "How to reach A+" suggestion box. Picks the
     * worst-scoring categories and surfaces their recommendations as
     * a numbered, actionable list. If the user is already at A or
     * A+, shows a celebratory state instead.
     */
    function renderSuggestionsBox(cats, privReport) {
        var wrap = el('div', { class: 'pcv2__suggestions-inner' });
        var header = el('div', { class: 'pcv2__suggestions-header' });
        header.appendChild(el('h3', {
            id: 'pcv2-suggestions-heading',
            class: 'pcv2__suggestions-title',
            text: PCV2.i18n.suggestionsTitle || 'How to reach A+'
        }));
        var overall = (typeof privReport.overall === 'number') ? privReport.overall : null;
        var currentGrade = privReport.grade || '—';
        var targetScore = 95;
        var targetGrade = 'A+';
        var scoreDelta = (overall != null) ? Math.max(0, targetScore - overall) : null;

        var status = el('div', {
            class: 'pcv2__suggestions-status',
            'data-pcv2-tone': scoreDelta === 0 ? 'safe' : (scoreDelta != null && scoreDelta <= 5 ? 'warning' : 'danger')
        });
        status.appendChild(el('span', {
            class: 'pcv2__suggestions-status-grade',
            text: currentGrade
        }));
        status.appendChild(el('span', {
            class: 'pcv2__suggestions-status-text',
            text: scoreDelta === 0
                ? (PCV2.i18n.suggestionsAlreadyAt || "You're at the top — keep your current setup.")
                : (overall != null
                    ? ((PCV2.i18n.suggestionsPointsAway || 'You are {delta} points away from {target}.'))
                        .replace('{delta}', String(scoreDelta))
                        .replace('{target}', targetGrade)
                    : (PCV2.i18n.suggestionsRunScan || 'Run a scan to see your score.'))
        }));
        header.appendChild(status);
        wrap.appendChild(header);

        // Build the action list. Sort by current score ascending
        // (worst first), filter out categories that are already at
        // 100 % (no improvement possible), and pair each with the
        // best recommendation we know about.
        var actionKeys = Object.keys(cats || {})
            .filter(function (k) {
                var c = cats[k];
                if (!c) return false;
                var s = Math.round(c.score || c.percent || 0);
                return s < 100;
            })
            .sort(function (a, b) {
                return (cats[a].score || cats[a].percent || 0)
                     - (cats[b].score || cats[b].percent || 0);
            });

        if (actionKeys.length === 0) {
            wrap.appendChild(el('p', {
                class: 'pcv2__suggestions-empty',
                text: PCV2.i18n.suggestionsAllMaxed || 'Every category is already at 100%. Privacy perfectionist!'
            }));
            return wrap;
        }

        var list = el('ol', { class: 'pcv2__suggestions-list' });
        var tierIcons = { danger: '✕', warning: '!', safe: '✓' };
        actionKeys.slice(0, 6).forEach(function (k, idx) {
            var c = cats[k];
            var scoreVal = Math.round(c.score || c.percent || 0);
            var sev = severityFromScore(scoreVal);
            // Projected delta: how many points the user could gain
            // by fixing this category. The conservative model is
            // (100 - currentScore) * weight / totalWeight, but
            // without weights we use a flat (100 - currentScore) /
            // countOfSub100Categories approximation. The exact
            // formula is documented inline.
            var item = el('li', {
                class: 'pcv2__suggestions-item',
                'data-pcv2-tone': sev
            });
            var head = el('div', { class: 'pcv2__suggestions-item-head' });
            head.appendChild(el('span', {
                class: 'pcv2__suggestions-item-rank',
                text: String(idx + 1).padStart(2, '0')
            }));
            head.appendChild(el('span', {
                class: 'pcv2__suggestions-item-label',
                text: prettySubLabel(k)
            }));
            head.appendChild(el('span', {
                class: 'pcv2__suggestions-item-score',
                'data-pcv2-tone': sev,
                text: tierIcons[sev] + ' ' + scoreVal + ' / 100'
            }));
            item.appendChild(head);
            var rec = pickRecommendation(c, k);
            if (rec) {
                item.appendChild(el('p', {
                    class: 'pcv2__suggestions-item-rec',
                    text: rec
                }));
            }
            list.appendChild(item);
        });
        wrap.appendChild(list);
        return wrap;
    }

    /* ---------- GeoTrace v2 renderer ----------------------------------- */

    function leafletAvailable() {
        return typeof window.L !== 'undefined' && typeof window.L.map === 'function';
    }

    function ensureLeaflet(cb) {
        if (leafletAvailable()) { cb(true); return; }
        if (!window.PC_SCAN || !window.PC_SCAN.assetUrl) { cb(false); return; }
        // Lazy-load Leaflet only when the user actually opens GeoTrace v2.
        var css = document.createElement('link');
        css.rel = 'stylesheet';
        css.href = window.PC_SCAN.assetUrl + 'css/leaflet.css';
        document.head.appendChild(css);
        var s = document.createElement('script');
        s.src = window.PC_SCAN.assetUrl + 'js/leaflet.js';
        s.onload = function () { cb(true); };
        s.onerror = function () { cb(false); };
        document.head.appendChild(s);
    }

    /**
     * Render a route on a 2D Leaflet map. Hops with null lat/lon are
     * treated as gaps: the polyline breaks at that hop and resumes at
     * the next geolocatable one. No fabricated points are drawn.
     */
    function renderRoute2D(route, container) {
        if (!leafletAvailable()) {
            container.innerHTML = '<div class="pcv2__geo-map-msg">' + (PCV2.i18n.geoUnavailable || 'Map unavailable') + '</div>';
            return;
        }
        container.innerHTML = '';
        var map = window.L.map(container, { worldCopyJump: true, scrollWheelZoom: false }).setView([20, 0], 2);

        // Phase 30 + 37: when the host element is on the dedicated
        // GeoTrace page (data-pcv2-route="geotrace"), prefer the
        // CartoDB Dark Matter basemap so the page matches
        // traceroute-online.com's wireframe — unless the admin
        // explicitly picked a non-OSM source in Settings → Map, in
        // which case we honour their choice (the dark UI works
        // equally well with CartoDB Voyager, ESRI Imagery, etc.).
        var isGeoPage = !!(container.closest && container.closest('[data-pcv2-route="geotrace"]'));
        var tileCfg = (typeof window.__pcGetTileConfig === 'function') ? window.__pcGetTileConfig() : null;
        var tileUrl, tileAttrib, tileMaxZoom, tileSub;
        if (isGeoPage && (!tileCfg || tileCfg.source === 'osm' || tileCfg.source === 'cartodb_dark')) {
            tileUrl = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
            tileAttrib = '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>';
            tileMaxZoom = 18; tileSub = 'abcd';
        } else if (tileCfg) {
            tileUrl = tileCfg.url;
            tileAttrib = tileCfg.attribution || '&copy; OpenStreetMap contributors';
            tileMaxZoom = tileCfg.maxZoom || 18;
            tileSub = tileCfg.subdomains || 'abc';
        } else {
            tileUrl = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
            tileAttrib = '&copy; OpenStreetMap contributors';
            tileMaxZoom = 18; tileSub = 'abc';
        }
        window.L.tileLayer(tileUrl, {
            attribution: tileAttrib,
            maxZoom: tileMaxZoom,
            subdomains: tileSub
        }).addTo(map);

        var publicPoints = [];
        var probe = route.probe && route.probe.lat != null ? route.probe : null;
        var target = route.target && route.target.lat != null ? route.target : null;
        var hops = Array.isArray(route.hops) ? route.hops : [];

        // Phase 30: accent palette for the dedicated GeoTrace page.
        var cAccent   = isGeoPage ? '#22D3EE' : '#1ea2c4';
        var cOrigin   = isGeoPage ? '#94A3B8' : '#5b6373';
        var cDest     = isGeoPage ? '#F472B6' : '#2ea043';
        var cPrivate  = isGeoPage ? '#475569' : '#8a93a3';

        // Build segments: contiguous runs of points that have coords.
        function addPoint(p, opts, hopIdx) {
            if (!p || p.lat == null || p.lon == null) return;
            var m = window.L.circleMarker([p.lat, p.lon], Object.assign({
                radius: opts && opts.origin ? 9 : opts && opts.dest ? 9 : 7,
                color: opts && opts.origin ? cOrigin
                      : opts && opts.dest   ? cDest
                      : opts && opts.private ? cPrivate
                      : cAccent,
                fillColor: opts && opts.origin ? cOrigin
                          : opts && opts.dest   ? cDest
                          : opts && opts.private ? cPrivate
                          : cAccent,
                fillOpacity: 0.95,
                weight: 2
            }, opts && opts.extra || {}));
            // Phase 30: number the hop markers (01, 02, …) when on the
            // dedicated page. The map becomes a legend for the table.
            if (isGeoPage && typeof hopIdx === 'number' && !(opts && (opts.origin || opts.dest))) {
                m.bindTooltip(
                    (hopIdx < 10 ? '0' : '') + hopIdx,
                    { permanent: true, direction: 'center', className: 'pcv2-geo-marker-label' }
                );
            }
            if (p.label || p.hostname) m.bindPopup(p.label || p.hostname);
            m.addTo(map);
            publicPoints.push([p.lat, p.lon]);
        }

        addPoint(probe, { origin: true });
        hops.forEach(function (h) {
            addPoint({ lat: h.lat, lon: h.lon, hostname: h.hostname, label: h.hostname || h.ip }, { private: h.status === 'private' }, h.index);
        });
        addPoint(target, { dest: true });

        // Draw segments connecting contiguous geolocatable points.
        var ordered = [];
        if (probe && probe.lat != null) ordered.push([probe.lat, probe.lon]);
        hops.forEach(function (h) {
            if (h.lat != null && h.lon != null) ordered.push([h.lat, h.lon]);
        });
        if (target && target.lat != null) ordered.push([target.lat, target.lon]);
        if (ordered.length >= 2) {
            window.L.polyline(ordered, { color: cAccent, weight: 3, opacity: 0.9, dashArray: null }).addTo(map);
            try { map.fitBounds(ordered, { padding: [30, 30] }); } catch (_e) {}
        }
    }

    function renderHopTimeline(route, container) {
        clear(container);
        var hops = Array.isArray(route.hops) ? route.hops : [];
        var prevRtt = null;
        hops.forEach(function (h) {
            var row = el('div', { class: 'pcv2__geo-hop', 'data-pcv2-hop': String(h.index) });
            row.appendChild(el('div', { class: 'pcv2__geo-hop-idx', text: String(h.index) }));
            var name = el('div', { class: 'pcv2__geo-hop-name' });
            if (h.status === 'unanswered') {
                name.appendChild(el('strong', { text: PCV2.i18n.unansweredBadge || 'No response' }));
                name.appendChild(el('span', { text: 'hop did not reply to traceroute probes' }));
            } else if (h.status === 'private') {
                name.appendChild(el('strong', { text: PCV2.i18n.privateBadge || 'Private' }));
                name.appendChild(el('span', { text: h.ip || '' }));
            } else {
                var city = h.city ? h.city + ', ' + h.country : (h.country || '—');
                name.appendChild(el('strong', { text: h.hostname || h.ip || '—' }));
                name.appendChild(el('span', { text: city + (h.asn ? ' · ' + h.asn : '') }));
            }
            row.appendChild(name);
            var rttText = h.rtt_ms == null ? '—' : (h.rtt_ms.toFixed(1) + ' ms');
            row.appendChild(el('div', { class: 'pcv2__geo-hop-rtt', text: rttText }));
            // Latency-jump heuristic: 1.5× previous hop's RTT.
            if (prevRtt != null && h.rtt_ms != null && prevRtt > 0 && h.rtt_ms > 1.5 * prevRtt) {
                row.setAttribute('data-pcv2-jump', 'true');
                row.appendChild(el('span', {
                    class: 'pcv2__chip--neutral',
                    title: 'RTT more than 1.5× the previous hop — likely a congested or distant link.',
                    text: PCV2.i18n.latencyJump || 'Latency jump'
                }));
            }
            if (h.status === 'public' && h.confidence && h.confidence !== 'unknown') {
                row.appendChild(el('span', { class: 'pcv2__chip--neutral', text: (PCV2.i18n.geoConfidence || 'Confidence') + ': ' + h.confidence }));
            }
            container.appendChild(row);
            if (h.rtt_ms != null) prevRtt = h.rtt_ms;
        });
        if (hops.length === 0) {
            container.appendChild(el('div', { class: 'pcv2__geo-hops-empty', text: PCV2.i18n.geoUnavailable || 'Traceroute unavailable' }));
        }
    }

    function renderRoute(route, host) {
        var mapEl    = host.querySelector('[data-pcv2-region="geo-map"]');
        var metaEl   = host.querySelector('[data-pcv2-region="geo-meta"]');
        var hopsEl   = host.querySelector('[data-pcv2-region="geo-hops"]');
        var discl    = host.querySelector('[data-pcv2-region="geo-disclaimer"]');
        var statsEl  = host.querySelector('[data-pcv2-region="geo-stats"]');
        // Meta.
        clear(metaEl);
        var meta = [
            [PCV2.i18n.geoProbeLabel || 'Probe', route.probe && (route.probe.city ? route.probe.city + ', ' + route.probe.country : route.probe && route.probe.ip)],
            [PCV2.i18n.geoTargetLabel || 'Destination', route.target && (route.target.hostname || (route.target.ip || '—'))],
            [PCV2.i18n.geoHopsLabel || 'Hops', String((route.hops || []).length)],
            ['Source kind', route.source_kind || '—']
        ];
        meta.forEach(function (m) {
            metaEl.appendChild(el('dt', { text: m[0] }));
            metaEl.appendChild(el('dd', { text: m[1] || '—' }));
        });
        if (discl) discl.textContent = PCV2.i18n.geoDisclaimer || '';

        // Phase 30: stats strip on the dedicated GeoTrace page.
        if (statsEl) {
            updateStatsStrip(route, statsEl);
        }

        // Map.
        if (route.hops && route.hops.length > 0) {
            ensureLeaflet(function (ok) {
                if (ok) renderRoute2D(route, mapEl);
                else mapEl.innerHTML = '<div class="pcv2__geotrace-map-msg">' + (PCV2.i18n.geoUnavailable || 'Map unavailable') + '</div>';
                // Phase 42: stash route + hops for the 3D globe toggle so
                // the user can flip to 3D without re-running the trace.
                try {
                    window.__pcLastGeoRoute = route;
                    window.__pcLastGeoHops  = Array.isArray(route.hops) ? route.hops : [];
                } catch (_e) { /* globalThis might be locked */ }
            });
        } else {
            mapEl.innerHTML = '<div class="pcv2__geotrace-map-msg">' + (PCV2.i18n.geoUnavailable || 'No traceroute data — paste your own below') + '</div>';
        }

        // Hop timeline / table.
        var isGeoPage = !!(host.getAttribute && host.getAttribute('data-pcv2-route') === 'geotrace');
        if (isGeoPage) {
            renderGeoHopsTable(route, hopsEl);
        } else {
            renderHopTimeline(route, hopsEl);
        }
    }

    /**
     * Phase 30: update the 4-tile stats strip on the dedicated GeoTrace
     * page (Hops / Last RTT / Networks / Total distance).
     */
    function updateStatsStrip(route, statsEl) {
        var hops = Array.isArray(route.hops) ? route.hops : [];
        var setStat = function (region, value) {
            var node = statsEl.querySelector('[data-pcv2-region="' + region + '"]');
            if (node) node.textContent = value;
        };
        // Hops reported.
        setStat('stat-hops', hops.length ? String(hops.length) : '—');

        // Last reply RTT: the RTT of the final hop that actually answered.
        var lastRtt = null;
        for (var i = hops.length - 1; i >= 0; i--) {
            if (hops[i].rtt_ms != null) { lastRtt = hops[i].rtt_ms; break; }
        }
        setStat('stat-rtt', lastRtt == null ? '—' : lastRtt.toFixed(2) + ' ms');

        // Networks observed: count distinct ASNs/AS orgs across public hops.
        var nets = {};
        hops.forEach(function (h) {
            if (h.status === 'public' && h.asn) {
                nets[h.asn] = true;
            } else if (h.status === 'public' && h.asn_org) {
                nets[h.asn_org] = true;
            }
        });
        var netCount = Object.keys(nets).length;
        setStat('stat-networks', netCount ? String(netCount) : '—');

        // Total distance: great-circle sum across contiguous geolocatable hops.
        var totalKm = computeTotalDistanceKm(route);
        setStat('stat-distance', totalKm > 0 ? Math.round(totalKm).toLocaleString() + ' km' : '—');

        // Reveal the strip once we have any data.
        if (route.hops && route.hops.length > 0) {
            statsEl.removeAttribute('hidden');
        }
    }

    /**
     * Great-circle distance between two lat/lon pairs (km). Used for the
     * "Total distance" KPI on the dedicated GeoTrace page.
     */
    function haversineKm(lat1, lon1, lat2, lon2) {
        if (lat1 == null || lon1 == null || lat2 == null || lon2 == null) return 0;
        var R = 6371;
        var toRad = function (d) { return d * Math.PI / 180; };
        var dLat = toRad(lat2 - lat1);
        var dLon = toRad(lon2 - lon1);
        var a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
                Math.sin(dLon / 2) * Math.sin(dLon / 2);
        var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }

    function computeTotalDistanceKm(route) {
        var hops = Array.isArray(route.hops) ? route.hops : [];
        var chain = [];
        if (route.probe && route.probe.lat != null) chain.push(route.probe);
        hops.forEach(function (h) {
            if (h.lat != null && h.lon != null) chain.push({ lat: h.lat, lon: h.lon });
        });
        if (route.target && route.target.lat != null) chain.push(route.target);
        var total = 0;
        for (var i = 1; i < chain.length; i++) {
            total += haversineKm(chain[i - 1].lat, chain[i - 1].lon, chain[i].lat, chain[i].lon);
        }
        return total;
    }

    /**
     * Phase 30: render the hop table on the dedicated GeoTrace page.
     * Columns: Hop / Router / Location / RTT / No-reply marker. Each
     * row mirrors the corresponding numbered map marker.
     */
    function renderGeoHopsTable(route, container) {
        clear(container);
        var hops = Array.isArray(route.hops) ? route.hops : [];
        if (hops.length === 0) {
            container.appendChild(el('div', { class: 'pcv2__geo-hops-empty', text: PCV2.i18n.geoUnavailable || 'Traceroute unavailable' }));
            return;
        }
        var table = el('table', { class: 'pcv2__geotrace-hops-table' });
        var thead = el('thead');
        var tr = el('tr');
        tr.appendChild(el('th', { text: 'Hop' }));
        tr.appendChild(el('th', { text: 'Router / network' }));
        tr.appendChild(el('th', { text: 'Location' }));
        tr.appendChild(el('th', { text: 'Avg RTT' }));
        thead.appendChild(tr);
        table.appendChild(thead);
        var tbody = el('tbody');
        hops.forEach(function (h) {
            var row = el('tr');
            var numCell = el('td', { class: 'hop-num mono', text: h.index < 10 ? '0' + h.index : String(h.index) });
            row.appendChild(numCell);
            var hostCell = el('td', { class: 'hop-host' });
            if (h.status === 'unanswered') {
                hostCell.appendChild(el('strong', { text: PCV2.i18n.unansweredBadge || 'No response' }));
            } else {
                var strong = el('strong', { text: h.hostname || h.ip || '—' });
                hostCell.appendChild(strong);
                if (h.asn) {
                    hostCell.appendChild(el('span', { class: 'hop-conf', text: h.asn }));
                }
            }
            row.appendChild(hostCell);
            var locCell = el('td', { class: 'hop-loc' });
            if (h.status === 'private') {
                locCell.textContent = PCV2.i18n.privateBadge || 'Private';
            } else {
                var city = h.city ? h.city + (h.country ? ', ' + h.country : '') : (h.country || '—');
                locCell.textContent = city;
            }
            row.appendChild(locCell);
            var rttCell = el('td', { class: 'hop-rtt mono' });
            if (h.rtt_ms == null) {
                rttCell.classList.add('hop-no-reply');
                rttCell.textContent = '—';
            } else {
                rttCell.textContent = h.rtt_ms.toFixed(2) + ' ms';
            }
            row.appendChild(rttCell);
            tbody.appendChild(row);
        });
        table.appendChild(tbody);
        container.appendChild(table);
    }

    /**
     * Attach the GeoTrace v2 widget to a host element. Wires the run
     * button (server-side traceroute) and the paste form (pasted text).
     */
    function bindGeoTrace(host) {
        var runBtn = host.querySelector('[data-pcv2-action="geo-run"]');
        var targetInput = host.querySelector('[data-pcv2-region="geo-target"]');
        var pasteForm = host.querySelector('[data-pcv2-action="geo-paste"]');
        var pasteTextarea = host.querySelector('[data-pcv2-region="geo-paste"]');

        function run() {
            var target = (targetInput && targetInput.value || '').trim() || (window.location.hostname);
            runBtn.disabled = true;
            fetch(window.PC_SCAN.restUrl + 'scan/geo/lookup?target=' + encodeURIComponent(target), {
                headers: { 'X-WP-Nonce': window.PC_SCAN.restNonce || '' }
            })
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function (route) { renderRoute(route, host); })
            .catch(function (err) {
                host.querySelector('[data-pcv2-region="geo-map"]').innerHTML =
                    '<div class="pcv2__geotrace-map-msg">' + (PCV2.i18n.geoUnavailable || 'Traceroute failed') + ' — ' + escape(err && err.message) + '</div>';
            })
            .then(function () { runBtn.disabled = false; });
        }

        if (runBtn) runBtn.addEventListener('click', run);
        // Phase 30: quick-destination chips on the dedicated page.
        host.querySelectorAll('[data-pcv2-geo-quick]').forEach(function (chip) {
            chip.addEventListener('click', function () {
                if (targetInput) {
                    targetInput.value = chip.getAttribute('data-pcv2-geo-quick') || '';
                }
                run();
            });
        });
        // Phase 42: 3D globe toggle — actually renders a Three.js / three-globe
        // view inside the existing map container, replacing the 2D
        // Leaflet tiles. Honors prefers-reduced-motion and falls back
        // gracefully when WebGL is unavailable. Reuses the v1 loader
        // (window.__pcLoadNetwork3dLibs) so we never load two copies
        // of three.js on the same page.
        var globeBtn = host.querySelector('[data-pcv2-action="geo-3d"]');
        if (globeBtn) {
            var geoGlobeActive = false;
            globeBtn.addEventListener('click', function () {
                var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
                if (reduced) {
                    window.alert(PCV2.i18n.geoPending || '3D globe disabled — your system prefers reduced motion.');
                    return;
                }
                var mapEl = host.querySelector('[data-pcv2-region="geo-map"]');
                if (!mapEl) return;
                if (geoGlobeActive) {
                    // Switch back: reload the route through renderRoute2D.
                    geoGlobeActive = false;
                    globeBtn.setAttribute('aria-pressed', 'false');
                    globeBtn.textContent = (PCV2.i18n && PCV2.i18n.geo3dLabel) || 'View in 3D globe';
                    if (window.__pcLastGeoRoute) {
                        renderRoute2D(window.__pcLastGeoRoute, mapEl);
                    }
                    return;
                }
                geoGlobeActive = true;
                globeBtn.setAttribute('aria-pressed', 'true');
                globeBtn.textContent = (PCV2.i18n && PCV2.i18n.geo2dLabel) || 'Back to 2D map';
                if (window.__pcEnsureNetwork3d) {
                    try {
                        window.__pcEnsureNetwork3d(mapEl, window.__pcLastGeoHops || []);
                    } catch (e) {
                        mapEl.innerHTML = '<div class="pcv2__geo-map-msg">3D globe could not be initialised.</div>';
                    }
                } else if (window.__pcLoadNetwork3dLibs) {
                    window.__pcLoadNetwork3dLibs().then(function () {
                        if (window.__pcEnsureNetwork3d) {
                            window.__pcEnsureNetwork3d(mapEl, window.__pcLastGeoHops || []);
                        }
                    });
                } else {
                    var libs = (typeof window.PC_GLOBE_LIBS === 'object' && window.PC_GLOBE_LIBS) || null;
                    if (libs && libs.three && libs.globe) {
                        lazyLoadThreeStandalone(mapEl, window.__pcLastGeoHops || []);
                    } else {
                        mapEl.innerHTML = '<div class="pcv2__geo-map-msg">3D libraries not configured. Add Three.js in Settings → Providers.</div>';
                    }
                }
            });
        }
        if (pasteForm && pasteTextarea) {
            pasteForm.addEventListener('submit', function (ev) {
                ev.preventDefault();
                fetch(window.PC_SCAN.restUrl + 'scan/geo/paste', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-WP-Nonce': window.PC_SCAN.restNonce || ''
                    },
                    body: JSON.stringify({ paste: pasteTextarea.value })
                })
                .then(function (r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.json();
                })
                .then(function (route) { renderRoute(route, host); })
                .catch(function (err) {
                    host.querySelector('[data-pcv2-region="geo-hops"]').innerHTML =
                        '<div class="pcv2__geo-hops-empty">' + escape(err && err.message) + '</div>';
                });
            });
        }
        // Render an initial honest empty state so the map area is never blank.
        renderRoute({ probe: null, target: null, hops: [], source_kind: 'unavailable' }, host);
    }

    /* ---------- boot ---------------------------------------------------- */

    /**
     * Read the persisted "Explain simply" preference. The toggle is
     * per-session: localStorage. Default is OFF (technical labels).
     */
    function readEli5Pref() {
        try { return window.localStorage.getItem('pcv2_eli5') === '1'; }
        catch (_e) { return false; }
    }
    function storeEli5Pref(on) {
        try { window.localStorage.setItem('pcv2_eli5', on ? '1' : '0'); }
        catch (_e) { /* localStorage blocked — preference is best-effort */ }
    }

    function initEli5Toggle() {
        // Apply the stored preference to the live state + DOM. We don't
        // re-render the whole report here — prettySubLabel() reads
        // PCV2.eli5Enabled on every call, and the next render (rescan,
        // theme switch, etc.) will pick it up. But we DO update the
        // visible labels on the already-rendered cards so the toggle
        // feels instant.
        PCV2.eli5Enabled = readEli5Pref();
        syncEli5Button();

        document.addEventListener('click', function (ev) {
            var btn = ev.target.closest('[data-pcv2-action="eli5-cycle"]');
            if (!btn) return;
            PCV2.eli5Enabled = !PCV2.eli5Enabled;
            storeEli5Pref(PCV2.eli5Enabled);
            syncEli5Button();
            // Re-run the report render so every visible label
            // (overview bar chart, finding rows, mini-card titles)
            // reflects the new mode. We pull the last report out of
            // the bar's __report stash, or fall back to a re-scan.
            reapplyEli5Labels();
        });
    }

    function syncEli5Button() {
        var btn = document.querySelector('.pcv2 [data-pcv2-action="eli5-cycle"]');
        if (!btn) return;
        btn.setAttribute('aria-pressed', PCV2.eli5Enabled ? 'true' : 'false');
        btn.title = PCV2.eli5Enabled
            ? (PCV2.i18n.eli5ToggleOn || 'Showing plain-language explanations')
            : (PCV2.i18n.eli5ToggleOff || 'Showing technical details');
        var lbl = btn.querySelector('.pcv2__eli5-toggle-label');
        if (lbl) lbl.textContent = PCV2.eli5Enabled ? 'ELI5 ✓' : 'ELI5';
    }

    /**
     * Re-render the score hero + bar chart + findings + cards using
     * the current ELI5 mode. We don't have a stored last-report handle
     * at module scope, so we walk the rendered DOM and rewrite the
     * static label slots. This is cheap and avoids re-running the
     * scan network round-trip.
     */
    function reapplyEli5Labels() {
        var dashboard = document.querySelector('[data-pcv2-component="dashboard"]');
        if (!dashboard) return;

        // Card titles — the cards are rendered server-side as static
        // articles with `data-pcv2-card`. We re-render the title only;
        // the body is more expensive to walk and the dynamic bits
        // (status chips, key/value rows) are data-bound.
        var titles = {
            overview:    PCV2.i18n.overviewTitle   || 'Overview',
            connection:  PCV2.i18n.connectionTitle || 'Connection',
            anonymity:   PCV2.i18n.anonymityTitle  || 'Anonymity',
            dns:         PCV2.i18n.dnsTitle        || 'DNS Resolver',
            browser:     PCV2.i18n.browserTitle    || 'Browser Privacy',
            security:    PCV2.i18n.securityTitle   || 'Security Findings'
        };
        Object.keys(titles).forEach(function (key) {
            var card = dashboard.querySelector('[data-pcv2-card="' + key + '"]');
            if (!card) return;
            var h = card.querySelector('[data-pcv2-region="card-title"]');
            if (h) h.textContent = titles[key];
        });

        // Bar chart labels — these are the per-category rows on the
        // Overview card. We have to know the original keys to map
        // them to the new labels, so we read the data attribute that
        // we stashed on each bar row during render (see
        // renderBarChart()).
        var bars = dashboard.querySelectorAll('.pcv2__bar-chart-row[data-pcv2-key]');
        bars.forEach(function (row) {
            var key = row.getAttribute('data-pcv2-key');
            var lbl = row.querySelector('.pcv2__bar-chart-label');
            if (key && lbl) lbl.textContent = prettySubLabel(key);
        });

        // Finding rows — the expandable Privacy Findings list also
        // stores the original key.
        var findings = dashboard.querySelectorAll('.pcv2__finding[data-pcv2-key]');
        findings.forEach(function (f) {
            var key = f.getAttribute('data-pcv2-key');
            var title = f.querySelector('.pcv2__finding-title');
            if (!key || !title) return;
            // The original title is "Label — NN / 100". Re-build it
            // from the stored score so we don't lose the number.
            var score = f.getAttribute('data-pcv2-score') || '';
            title.textContent = prettySubLabel(key) + (score ? ' — ' + score + ' / 100' : '');
        });

        // Mini-card labels on the score hero (sub-score titles).
        var miniCards = dashboard.querySelectorAll('.pcv2__mini-card[data-pcv2-key]');
        miniCards.forEach(function (c) {
            var key = c.getAttribute('data-pcv2-key');
            var lbl = c.querySelector('.pcv2__mini-card-label');
            if (key && lbl) lbl.textContent = prettySubLabel(key);
        });

        // Radial-chart legend rows on the new score hero.
        var legendRows = dashboard.querySelectorAll('.pcv2__radial-legend-row[data-pcv2-key]');
        legendRows.forEach(function (row) {
            var key = row.getAttribute('data-pcv2-key');
            var lbl = row.querySelector('.pcv2__radial-legend-label');
            if (key && lbl) lbl.textContent = prettySubLabel(key);
        });

        // Radial chart SVG <text> labels around the perimeter — they
        // only hold the visible text node, so rewrite in place.
        var svgLabels = dashboard.querySelectorAll('.pcv2__radial-label');
        // Match by index against legend rows since we don't put a key
        // on the SVG <text> (too easy for screen readers to confuse).
        svgLabels.forEach(function (labelEl, idx) {
            var row = legendRows[idx];
            if (!row) return;
            var key = row.getAttribute('data-pcv2-key');
            if (key) labelEl.textContent = prettySubLabel(key);
        });
    }

    function initThemeToggle() {
        applyTheme(readStoredTheme());
        // React to system theme changes while in 'system' mode.
        if (window.matchMedia) {
            var mq = window.matchMedia('(prefers-color-scheme: dark)');
            var handler = function () {
                if (readStoredTheme() === 'system') applyTheme('system');
            };
            if (mq.addEventListener) mq.addEventListener('change', handler);
            else if (mq.addListener) mq.addListener(handler);
        }
        document.addEventListener('click', function (ev) {
            var btn = ev.target.closest('[data-pcv2-action="theme-cycle"]');
            if (!btn) return;
            var cur = readStoredTheme();
            var nxt = nextTheme(cur);
            storeTheme(nxt);
            applyTheme(nxt);
        });
    }

    function initDashboard() {
        var dashboard = document.querySelector('[data-pcv2-component="dashboard"]');
        if (!dashboard) return;
        // Wire the main CTA.
        var cta = dashboard.querySelector('[data-pcv2-action="start-scan"]');
        if (cta) cta.addEventListener('click', function () { runScan(dashboard); });

        // GeoTrace widget, if present on this page.
        var geo = document.querySelector('[data-pcv2-component="geotrace"]');
        if (geo) bindGeoTrace(geo);

        // Phase 42: top-nav GeoTrace link scrolls the user down to the
        // inline geotrace section if it's on this page, otherwise it
        // deep-links to the standalone /geotrace/ page (set in the
        // <a> href by the shortcode). Same UX for both cases.
        document.addEventListener('click', function (ev) {
            var t = ev.target.closest('[data-pcv2-action="open-geotrace"]');
            if (!t) return;
            var target = document.querySelector('[data-pcv2-component="geotrace"]');
            if (target) {
                ev.preventDefault();
                try { target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
                catch (_e) { target.scrollIntoView(); }
            }
        });

        // If a `data-pcv2-autostart="1"` attribute is present, fire the
        // scan immediately. (Manual-only otherwise.)
        if (dashboard.getAttribute('data-pcv2-autostart') === '1') {
            runScan(dashboard);
        }
    }

    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    ready(function () {
        initEli5Toggle();
        initThemeToggle();
        initCopyIpButtons();
        initDashboard();
        PCV2.initialized = true;
    });

    /**
     * Wire up the "copy IP" button on the Connection card. We use a
     * single delegated click listener so we don't have to re-bind on
     * every scan re-render. The clipboard write is best-effort — if
     * the Clipboard API is blocked, we flash a "✕" state on the
     * button so the user knows it didn't work.
     */
    function initCopyIpButtons() {
        document.addEventListener('click', function (ev) {
            // The same handler covers both copy-ip and copy-ua actions.
            var btn = ev.target.closest('[data-pcv2-action="copy-ip"], [data-pcv2-action="copy-ua"]');
            if (!btn) return;
            ev.preventDefault();
            var value = btn.getAttribute('data-pcv2-ip') || btn.getAttribute('data-pcv2-ua') || '';
            if (!value) return;
            var original = btn.textContent;
            var done = function (ok) {
                btn.textContent = ok ? '✓' : '✕';
                btn.classList.add(ok ? 'pcv2__connection-ip-copy--ok' : 'pcv2__connection-ip-copy--err');
                setTimeout(function () {
                    btn.textContent = original;
                    btn.classList.remove('pcv2__connection-ip-copy--ok', 'pcv2__connection-ip-copy--err');
                }, 1400);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(value).then(function () { done(true); }, function () { done(false); });
            } else {
                try {
                    var ta = document.createElement('textarea');
                    ta.value = value;
                    ta.style.position = 'fixed';
                    ta.style.opacity = '0';
                    document.body.appendChild(ta);
                    ta.focus();
                    ta.select();
                    var ok = document.execCommand && document.execCommand('copy');
                    document.body.removeChild(ta);
                    done(!!ok);
                } catch (_e) {
                    done(false);
                }
            }
        });
    }

    window.PCV2 = PCV2;

    // Phase 42 — Network Path card on the v2 dashboard.
    //
    // The v1 scanner exposes `window.__pcLastNetworkHops` after each
    // render. The v2 page can be opened in isolation (no v1 scanner
    // loaded), so we also accept a hops array stashed on PCV2 by a
    // future v2-native scan pipeline. For now: if v1 has rendered
    // (the same page often loads both scanners), borrow the hops.
    function getV2NetworkHops() {
        if (Array.isArray(window.__pcLastNetworkHops) && window.__pcLastNetworkHops.length) {
            return window.__pcLastNetworkHops;
        }
        return [];
    }

    function renderV2NetworkPath(card, hops) {
        if (!card) return;
        var body = card.querySelector('[data-pcv2-region="card-body"]');
        var twoD = card.querySelector('[data-pcv2-region="network-2d"]');
        var threeD = card.querySelector('[data-pcv2-region="network-3d"]');
        if (!body || !twoD || !threeD) return;
        clear(twoD);
        clear(threeD);

        // Build a lightweight 2D node/edge diagram (not a full
        // Leaflet map — this is the inline card view, so we keep
        // it self-contained as an SVG).
        var svgNS = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', '0 0 100 24');
        svg.setAttribute('class', 'pcv2__network-svg');
        svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
        var w = 100 / Math.max(1, hops.length - 1);
        var nodes = hops.map(function (h, i) {
            var cx = i * w;
            var cy = 12 + (h.latency_ms ? Math.min(8, h.latency_ms / 30) : 0) * 0.4;
            var fill = (h.loss_pct && h.loss_pct > 0) ? '#F87171' : '#22D3EE';
            var c = document.createElementNS(svgNS, 'circle');
            c.setAttribute('cx', String(cx));
            c.setAttribute('cy', String(cy));
            c.setAttribute('r', '1.2');
            c.setAttribute('fill', fill);
            c.setAttribute('stroke', '#0F172A');
            c.setAttribute('stroke-width', '0.18');
            svg.appendChild(c);
            return { cx: cx, cy: cy, hop: h };
        });
        for (var i = 1; i < nodes.length; i++) {
            var ln = document.createElementNS(svgNS, 'line');
            ln.setAttribute('x1', String(nodes[i - 1].cx));
            ln.setAttribute('y1', String(nodes[i - 1].cy));
            ln.setAttribute('x2', String(nodes[i].cx));
            ln.setAttribute('y2', String(nodes[i].cy));
            ln.setAttribute('stroke', '#94A3B8');
            ln.setAttribute('stroke-width', '0.18');
            svg.appendChild(ln);
        }
        // Numbered hop labels.
        nodes.forEach(function (n, i) {
            var t = document.createElementNS(svgNS, 'text');
            t.setAttribute('x', String(n.cx));
            t.setAttribute('y', '23');
            t.setAttribute('text-anchor', 'middle');
            t.setAttribute('font-size', '2');
            t.setAttribute('fill', '#94A3B8');
            t.setAttribute('font-family', 'JetBrains Mono, Menlo, monospace');
            t.textContent = String(i + 1).padStart(2, '0');
            svg.appendChild(t);
        });
        twoD.appendChild(svg);

        // Compact hop table beneath the SVG.
        var table = el('table', { class: 'pcv2__network-table' });
        var tbody = el('tbody');
        hops.forEach(function (h, i) {
            var tr = el('tr', {});
            tr.appendChild(el('td', { class: 'pcv2__network-table-num mono', text: String(i + 1).padStart(2, '0') }));
            tr.appendChild(el('td', { class: 'pcv2__network-table-name', text: h.name || h.host || 'hop ' + (i + 1) }));
            tr.appendChild(el('td', { class: 'pcv2__network-table-rtt mono', text: (h.latency_ms != null ? h.latency_ms + ' ms' : '—') }));
            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        twoD.appendChild(table);
    }

    function initV2NetworkPath() {
        var card = document.querySelector('[data-pcv2-card="network-path"]');
        if (!card) return;
        var hops = getV2NetworkHops();
        if (!hops.length) {
            card.hidden = true;
            return;
        }
        card.hidden = false;
        renderV2NetworkPath(card, hops);

        // 2D/3D toggle. The 3D view uses the same Three.js + three-globe
        // libraries the v1 Network Path uses, lazy-loaded once via the
        // shared PC_GLOBE_LIBS localize bag. If three.js isn't available
        // (not yet loaded, or visitor opted out of motion), the toggle
        // stays disabled and the 2D view is the only view.
        var toggle = card.querySelector('[data-pcv2-action="network-mode-toggle"]');
        var twoD = card.querySelector('[data-pcv2-region="network-2d"]');
        var threeD = card.querySelector('[data-pcv2-region="network-3d"]');
        if (!toggle || !twoD || !threeD) return;

        toggle.addEventListener('click', function () {
            var want3d = toggle.getAttribute('aria-pressed') !== 'true';
            if (want3d && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
                window.alert('3D Network Path is disabled — your system prefers reduced motion.');
                return;
            }
            toggle.setAttribute('aria-pressed', want3d ? 'true' : 'false');
            var dot = toggle.querySelector('.pcv2__network-mode-dot');
            var suf = toggle.querySelector('.pcv2__network-mode-suffix');
            if (dot) dot.textContent = want3d ? '3D' : '2D';
            if (suf) suf.textContent = want3d ? ' / 2D' : ' / 3D';
            toggle.title = want3d ? 'Switch back to 2D' : 'Switch to 3D globe';
            twoD.hidden = want3d;
            threeD.hidden = !want3d;
            if (want3d) {
                // Lazy-load three.js + three-globe via the v1 scanner's
                // loader. The v2 IIFE doesn't import the libraries
                // itself — it asks the v1 IIFE to render — so we never
                // load two copies of three.js on the same page.
                if (window.__pcEnsureNetwork3d) {
                    try { window.__pcEnsureNetwork3d(threeD, hops); }
                    catch (e) {
                        threeD.innerHTML = '<p class="pcv2__network-3d-pending">3D view could not be initialised.</p>';
                    }
                } else if (window.__pcLoadNetwork3dLibs) {
                    window.__pcLoadNetwork3dLibs().then(function () {
                        if (window.__pcEnsureNetwork3d) {
                            window.__pcEnsureNetwork3d(threeD, hops);
                        }
                    });
                } else {
                    // No v1 scanner on this page — lazy-load three.js
                    // ourselves so the v2 standalone page still gets a
                    // working 3D view.
                    threeD.innerHTML = '<p class="pcv2__network-3d-pending">Loading 3D view…</p>';
                    lazyLoadThreeStandalone(threeD, hops);
                }
            }
        });
    }

    // Watch for v1 hops arriving after first paint (the v1 scanner
    // usually finishes a beat after DOMContentLoaded). Polling is
    // cheaper than wiring a mutation observer here because the card
    // stays in the DOM.
    function watchV2NetworkHops() {
        var attempts = 0;
        var poll = setInterval(function () {
            attempts++;
            var card = document.querySelector('[data-pcv2-card="network-path"]');
            if (!card) { clearInterval(poll); return; }
            var hops = getV2NetworkHops();
            if (hops.length) {
                card.hidden = false;
                renderV2NetworkPath(card, hops);
                clearInterval(poll);
            } else if (attempts > 60) {
                // ~30s — give up so the card stays hidden instead of
                // flickering forever.
                clearInterval(poll);
            }
        }, 500);
    }

    // Hook the network path card up after DOM ready.
    ready(function () {
        initV2NetworkPath();
        watchV2NetworkHops();
    });

    // Lazy-load three.js + three-globe on v2-only pages (no v1 scanner).
    // Reuses the same PC_GLOBE_LIBS localize bag the v1 scanner reads.
    function lazyLoadThreeStandalone(container, hops) {
        var libs = (typeof window.PC_GLOBE_LIBS === 'object' && window.PC_GLOBE_LIBS) || null;
        if (!libs || !libs.three || !libs.globe) {
            container.innerHTML = '<p class="pcv2__network-3d-pending">3D view libraries not configured.</p>';
            return;
        }
        function inject(src) {
            return new Promise(function (resolve, reject) {
                var s = document.createElement('script');
                s.src = src;
                s.async = true;
                s.onload = function () { resolve(); };
                s.onerror = function () { reject(new Error('Failed to load ' + src)); };
                document.head.appendChild(s);
            });
        }
        inject(libs.three).then(function () { return inject(libs.globe); })
            .then(function () {
                // three-globe needs a small render bridge. The v1
                // renderNetwork3d() is the only implementation we
                // ship, and it's gated behind the v1 IIFE. If v1
                // isn't on this page we render a minimal Three.js
                // scene showing the hops as a sphere with arcs.
                if (window.__pcRenderNetwork3d) {
                    window.__pcRenderNetwork3d(container, hops);
                } else {
                    renderThreeFallback(container, hops);
                }
            })
            .catch(function () {
                container.innerHTML = '<p class="pcv2__network-3d-pending">3D view could not load — staying on 2D.</p>';
            });
    }

    function renderThreeFallback(container, hops) {
        try {
            var w = container.clientWidth || 600;
            var h = container.clientHeight || 320;
            var scene = new window.THREE.Scene();
            var camera = new window.THREE.PerspectiveCamera(45, w / h, 0.1, 1000);
            camera.position.z = 320;
            var renderer = new window.THREE.WebGLRenderer({ antialias: true, alpha: true });
            renderer.setSize(w, h);
            renderer.setPixelRatio(window.devicePixelRatio || 1);
            container.innerHTML = '';
            container.appendChild(renderer.domElement);

            var geo = new window.THREE.SphereGeometry(140, 32, 32);
            var mat = new window.THREE.MeshBasicMaterial({
                color: 0x0F172A,
                wireframe: true,
                transparent: true,
                opacity: 0.45
            });
            scene.add(new window.THREE.Mesh(geo, mat));

            hops.forEach(function (hop) {
                if (hop.lat == null || hop.lng == null) return;
                var phi   = (90 - hop.lat) * Math.PI / 180;
                var theta = (hop.lng + 180) * Math.PI / 180;
                var r = 145;
                var dot = new window.THREE.Mesh(
                    new window.THREE.SphereGeometry(2.2, 12, 12),
                    new window.THREE.MeshBasicMaterial({ color: 0x22D3EE })
                );
                dot.position.set(
                    -r * Math.sin(phi) * Math.cos(theta),
                    r * Math.cos(phi),
                    r * Math.sin(phi) * Math.sin(theta)
                );
                scene.add(dot);
            });
            function tick() {
                requestAnimationFrame(tick);
                scene.rotation.y += 0.0025;
                renderer.render(scene, camera);
            }
            tick();
            container.__pcThreeFallback = true;
        } catch (e) {
            container.innerHTML = '<p class="pcv2__network-3d-pending">3D rendering failed in this browser.</p>';
        }
    }
})();
