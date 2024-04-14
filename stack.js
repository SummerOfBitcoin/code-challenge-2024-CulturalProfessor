const stackItems = new WeakMap();

class Stack {
    constructor() {
        stackItems.set(this, []);
    }

    push(element) {
        const items = stackItems.get(this);
        items.push(element);
    }

    pop() {
        const items = stackItems.get(this);
        if (items.length == 0)
            return "Underflow";
        return items.pop();
    }

    peek() {
        const items = stackItems.get(this);
        return items[items.length - 1];
    }

    isEmpty() {
        const items = stackItems.get(this);
        return items.length == 0;
    }

    printStack() {
        const items = stackItems.get(this);
        let str = "";
        for (let i = 0; i < items.length; i++) {
            str += items[i] + " ";
        }
        return str;
    }
    size() {
        const items = stackItems.get(this);
        return items.length;
    }
}


export { Stack };