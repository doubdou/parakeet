
#ifndef __WAV_ANALYSIS_H_
#define __WAV_ANALYSIS_H_

/* wave音频头以小端字节序进行存储 */

#ifdef __cplusplus
extern "C"
{
#endif
typedef struct WAV_RIFF 
{
    char ChunkID[4];
    unsigned int ChunkSize; 
    char Format[4]; 
} RIFF_t;

typedef struct WAV_FMT 
{
    unsigned char Subchunk1ID[4]; 
    unsigned int Subchunk1Size; 
    unsigned short AudioFormat;   
    unsigned short NumChannels;  
    unsigned int SampleRate;   
    unsigned int ByteRate;
    unsigned short BlockAlign; 
    unsigned short BitsPerSample;
} FMT_t;

typedef struct WAV_HEADER
{
    RIFF_t riff;
    FMT_t fmt;
} HEADER_t;

typedef struct WAV_CHUNK
{
    char Subchunk2ID[4];
    unsigned int Subchunk2Size;
} CHUNK_t;

typedef struct WAV_READER
{
    unsigned int channel;
    unsigned int sampleRate;
    unsigned int sampleBits;
    unsigned int pcmSize;
    unsigned char pcmData[0];
}READER_t;

//初始化
READER_t * wav_reader_init(void * audio, unsigned int size);

//释放reader结构
void wav_reader_close(READER_t *reader);

#ifdef __cplusplus
}
#endif

#endif
