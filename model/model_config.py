import torch
import transformers
'''
Configs of the model taken on hugging face. 

                                                                            DO NOT TOUCH!

'''


model_id = "vanessasml/cyber-risk-llama-3-8b"

pipeline = transformers.pipeline(
    "text-generation",
    model=model_id,
    model_kwargs={"torch_dtype": torch.bfloat16,
                "device_map": "auto",
                "offload_folder": "./offload"
            }
)
def cyber_exp_model(input):
    messages = [
        {"role": "system", "content": "You are a penetration testing expert."},
        {"role": "user", "content": input},
    ]

    prompt = pipeline.tokenizer.apply_chat_template(
            messages, 
            tokenize=False, 
            add_generation_prompt=True
    )

    terminators = [
        pipeline.tokenizer.eos_token_id,
        pipeline.tokenizer.convert_tokens_to_ids("<|eot_id|>")
    ]

    outputs = pipeline(
        prompt,
        max_new_tokens=500,
        eos_token_id=terminators,
        do_sample=True,
        temperature=0.1,
        top_p=0.9,
    )
    return outputs[0]["generated_text"][len(prompt):]
