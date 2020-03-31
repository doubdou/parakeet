
#include "audioparse/wav_analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

//初始化
READER_t * wav_reader_init(void * audio, unsigned int size)
{
    HEADER_t header;
    READER_t *reader = NULL;
    CHUNK_t chunk;
    unsigned int offset = 0;
    unsigned int pcmSize = 0;

    if (NULL == audio || 0 == size)
    {
        return NULL;
    }

    memcpy(&header, audio, sizeof(HEADER_t));

    if (0 != strncmp(header.riff.ChunkID, "RIFF", sizeof(header.riff.ChunkID)))
    {
        return NULL;
    }
    if (0 != strncmp(header.riff.Format, "WAVE", sizeof(header.riff.Format)))
    {
        return NULL;
    }
    offset += sizeof(HEADER_t);

    while (1)
    {
        memcpy(&chunk, (unsigned char *)audio + offset, sizeof(CHUNK_t));
        if (0 == strncmp(chunk.Subchunk2ID, "data", sizeof(chunk.Subchunk2ID)))
        {
            break;
        }
        if (chunk.Subchunk2Size  > size - offset)
        {
            //数据错误，退出
            break;
        }
        offset += sizeof(CHUNK_t) + chunk.Subchunk2Size;
    }

    offset += sizeof(CHUNK_t);
    if (chunk.Subchunk2Size > size - offset)
    {
        pcmSize = size - offset;
    }
    else
    {
        pcmSize = chunk.Subchunk2Size;
    }

    reader = calloc(1, sizeof(READER_t) + pcmSize);
    assert(reader);

    reader->channel = header.fmt.NumChannels;
    reader->sampleRate = header.fmt.SampleRate;
    reader->sampleBits = header.fmt.BitsPerSample;
    reader->pcmSize = pcmSize;

    memcpy((unsigned char *)reader + sizeof(READER_t), (unsigned char *)audio + offset, pcmSize);

    return reader;
}

//释放reader结构
void wav_reader_close(READER_t *reader)
{
    if (reader)
    {
        free(reader);
        reader = NULL;
    }
}













