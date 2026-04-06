import numpy as np, wave

def decode_wav(filename):
    with wave.open(filename, 'r') as wf:
        samples = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
    
    samples_per_char = int(44100 * 0.12)  # = 5292
    result = []
    for i in range(len(samples) // samples_per_char):
        chunk = samples[i*samples_per_char:(i+1)*samples_per_char].astype(float)
        freqs = np.fft.rfftfreq(len(chunk), 1.0/44100)
        dominant_freq = freqs[np.argmax(np.abs(np.fft.rfft(chunk)))]
        
        byte_val = round((dominant_freq - 500.0) / 9.0)
        char = ((byte_val - 0x11) & 0xFF) ^ 0xa5
        result.append(chr(char))
    
    return ''.join(result)

print(decode_wav('file.bin'))
